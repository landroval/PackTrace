package projectinventory

import (
	"context"
	"errors"
	"io"
	"path"
	"strings"

	"packtrace/internal/nativefs"
)

type bunCacheIndex struct {
	root  *nativefs.Root
	peers map[[32]byte][]string
}

// Only enumerate cache package directories and package.json metadata. Generic
// package contents, credentials and config files are never opened as content.
func indexBunCache(ctx context.Context, root *nativefs.Root) (*bunCacheIndex, error) {
	idx := &bunCacheIndex{root: root, peers: map[[32]byte][]string{}}
	dirs := []string{"."}
	entries, names := 0, 0
	for len(dirs) > 0 {
		name := dirs[len(dirs)-1]
		dirs = dirs[:len(dirs)-1]
		cursor, err := root.OpenDirectoryMetadata(ctx, name)
		if err != nil {
			return nil, err
		}
		for {
			batch, err := cursor.Next()
			if err != nil && err != io.EOF {
				cursor.Close()
				return nil, err
			}
			for _, entry := range batch {
				entries++
				names += len(entry.Name)
				if entries > maxEntries || names > maxNames {
					cursor.Close()
					return nil, nativefs.ErrLimit
				}
				base := path.Base(entry.Name)
				if entry.Kind != nativefs.KindDirectory || strings.HasPrefix(base, ".") {
					continue
				}
				if name == "." && strings.HasPrefix(base, "@") && !strings.Contains(base[1:], "@") {
					dirs = append(dirs, entry.Name)
					continue
				}
				peer := entry.Name + "/package.json"
				entries++
				names += len(peer)
				if entries > maxEntries || names > maxNames {
					cursor.Close()
					return nil, nativefs.ErrLimit
				}
				metadata, e := root.OpenMetadata(ctx, peer)
				if e != nil {
					continue
				} // No counterpart admission is inferred from absence/failure.
				key, e := metadata.ObjectKey()
				closeErr := metadata.Close()
				if closeErr != nil {
					cursor.Close()
					return nil, closeErr
				}
				if e == nil {
					idx.peers[key] = append(idx.peers[key], peer)
				}
			}
			if err == io.EOF {
				break
			}
		}
		if err := cursor.Close(); err != nil {
			return nil, err
		}
	}
	return idx, nil
}

func (b *bunCacheIndex) open(ctx context.Context, root *nativefs.Root, name string, limit int64) (*nativefs.File, error) {
	metadata, err := root.OpenMetadata(ctx, name)
	if err != nil {
		return nil, err
	}
	key, keyErr := metadata.ObjectKey()
	closeErr := metadata.Close()
	if keyErr != nil || closeErr != nil {
		return nil, errors.Join(keyErr, closeErr)
	}
	peers := b.peers[key]
	if len(peers) != 1 {
		return nil, nativefs.ErrPath
	}
	return root.OpenPairedManifest(ctx, name, b.root, peers[0], limit)
}
