//go:build linux && (amd64 || arm64)

package nativefs

func (r *nativeRoot) captureMetadata(name string) (*object, error) {
	if e := r.guard(); e != nil {
		return nil, e
	}
	f, s, e := r.capture(name, false)
	if e != nil {
		return nil, e
	}
	o := &object{handle: f, initial: s}
	if s.kind() == KindLink {
		o.target, e = readlinkHandle(f)
		if e != nil {
			o.close()
			return nil, e
		}
	}
	return o, nil
}
