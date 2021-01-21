/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

/*
   Copyright 2019 The Go Authors. All rights reserved.
   Use of this source code is governed by a BSD-style
   license that can be found in the LICENSE file.
*/

package estargz

import (
	"archive/tar"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	digest "github.com/opencontainers/go-digest"
)

const (
	// TOCTarName is the name of the JSON file in the tar archive in the
	// table of contents gzip stream.
	TOCTarName = "stargz.index.json"

	// FooterSize is the number of bytes in the footer
	//
	// The footer is an empty gzip stream with no compression and an Extra
	// header of the form "%016xSTARGZ", where the 64 bit hex-encoded
	// number is the offset to the gzip stream of JSON TOC.
	//
	// 51 comes from:
	//
	// 10 bytes  gzip header
	// 2  bytes  XLEN (length of Extra field) = 26 (4 bytes header + 16 hex digits + len("STARGZ"))
	// 2  bytes  Extra: SI1 = 'S', SI2 = 'G'
	// 2  bytes  Extra: LEN = 22 (16 hex digits + len("STARGZ"))
	// 22 bytes  Extra: subfield = fmt.Sprintf("%016xSTARGZ", offsetOfTOC)
	// 5  bytes  flate header
	// 8  bytes  gzip footer
	// (End of the eStargz blob)
	//
	// NOTE: For Extra fields, subfield IDs SI1='S' SI2='G' is used for eStargz.
	FooterSize = 51

	// legacyFooterSize is the number of bytes in the legacy stargz footer.
	//
	// 47 comes from:
	//
	//   10 byte gzip header +
	//   2 byte (LE16) length of extra, encoding 22 (16 hex digits + len("STARGZ")) == "\x16\x00" +
	//   22 bytes of extra (fmt.Sprintf("%016xSTARGZ", tocGzipOffset))
	//   5 byte flate header
	//   8 byte gzip footer (two little endian uint32s: digest, size)
	legacyFooterSize = 47

	// TOCJSONDigestAnnotation is an annotation for an image layer. This stores the
	// digest of the TOC JSON.
	// This annotation is valid only when it is specified in `.[]layers.annotations`
	// of an image manifest.
	TOCJSONDigestAnnotation = "containerd.io/snapshot/stargz/toc.digest"

	// PrefetchLandmark is a file entry which indicates the end position of
	// prefetch in the stargz file.
	PrefetchLandmark = ".prefetch.landmark"

	// NoPrefetchLandmark is a file entry which indicates that no prefetch should
	// occur in the stargz file.
	NoPrefetchLandmark = ".no.prefetch.landmark"

	landmarkContents = 0xf
	EmptyFileHash    = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// jtoc is the JSON-serialized table of contents index of the files in the stargz file.
type jtoc struct {
	Version int         `json:"version"`
	Entries []*TOCEntry `json:"entries"`
}

// TOCEntry is an entry in the stargz file's TOC (Table of Contents).
type TOCEntry struct {
	// Name is the tar entry's name. It is the complete path
	// stored in the tar file, not just the base name.
	Name string `json:"name"`

	// Type is one of "dir", "reg", "symlink", "hardlink", "char",
	// "block", "fifo", or "chunk".
	// The "chunk" type is used for regular file data chunks past the first
	// TOCEntry; the 2nd chunk and on have only Type ("chunk"), Offset,
	// ChunkOffset, and ChunkSize populated.
	Type string `json:"type"`

	// Size, for regular files, is the logical size of the file.
	Size int64 `json:"size,omitempty"`

	// ModTime3339 is the modification time of the tar entry. Empty
	// means zero or unknown. Otherwise it's in UTC RFC3339
	// format. Use the ModTime method to access the time.Time value.
	ModTime3339 string `json:"modtime,omitempty"`
	modTime     time.Time

	// LinkName, for symlinks and hardlinks, is the link target.
	LinkName string `json:"linkName,omitempty"`

	// Mode is the permission and mode bits.
	Mode int64 `json:"mode,omitempty"`

	// UID is the user ID of the owner.
	UID int `json:"uid,omitempty"`

	// GID is the group ID of the owner.
	GID int `json:"gid,omitempty"`

	// Uname is the username of the owner.
	//
	// In the serialized JSON, this field may only be present for
	// the first entry with the same UID.
	Uname string `json:"userName,omitempty"`

	// Gname is the group name of the owner.
	//
	// In the serialized JSON, this field may only be present for
	// the first entry with the same GID.
	Gname string `json:"groupName,omitempty"`

	// Offset, for regular files, provides the offset in the
	// stargz file to the file's data bytes. See ChunkOffset and
	// ChunkSize.
	Offset int64 `json:"offset,omitempty"`

	nextOffset int64 // the Offset of the next entry with a non-zero Offset

	// DevMajor is the major device number for "char" and "block" types.
	DevMajor int `json:"devMajor,omitempty"`

	// DevMinor is the major device number for "char" and "block" types.
	DevMinor int `json:"devMinor,omitempty"`

	// NumLink is the number of entry names pointing to this entry.
	// Zero means one name references this entry.
	NumLink int

	// Xattrs are the extended attribute for the entry.
	Xattrs map[string][]byte `json:"xattrs,omitempty"`

	// Digest stores the OCI checksum for regular files payload.
	// It has the form "sha256:abcdef01234....".
	Digest string `json:"digest,omitempty"`

	// ChunkOffset is non-zero if this is a chunk of a large,
	// regular file. If so, the Offset is where the gzip header of
	// ChunkSize bytes at ChunkOffset in Name begin.
	//
	// In serialized form, a "chunkSize" JSON field of zero means
	// that the chunk goes to the end of the file. After reading
	// from the stargz TOC, though, the ChunkSize is initialized
	// to a non-zero file for when Type is either "reg" or
	// "chunk".
	ChunkOffset int64 `json:"chunkOffset,omitempty"`
	ChunkSize   int64 `json:"chunkSize,omitempty"`

	// ChunkDigest stores an OCI digest of the chunk. This must be formed
	// as "sha256:0123abcd...".
	ChunkDigest string `json:"chunkDigest,omitempty"`

	CompressedSize int64 `json:"compressedSize,omitempty"`

	sourceLayer int
	landmark    int

	children map[string]*TOCEntry
}

// ModTime returns the entry's modification time.
func (e *TOCEntry) ModTime() time.Time { return e.modTime }

// NextOffset returns the position (relative to the start of the
// stargz file) of the next gzip boundary after e.Offset.
func (e *TOCEntry) NextOffset() int64 { return e.nextOffset }

// Stat returns a FileInfo value representing e.
func (e *TOCEntry) Stat() os.FileInfo { return fileInfo{e} }

func (e *TOCEntry) Landmark() int { return e.landmark }

// ForeachChild calls f for each child item. If f returns false, iteration ends.
// If e is not a directory, f is not called.
func (e *TOCEntry) ForeachChild(f func(baseName string, ent *TOCEntry) bool) {
	for name, ent := range e.children {
		if !f(name, ent) {
			return
		}
	}
}

// LookupChild returns the directory e's child by its base name.
func (e *TOCEntry) LookupChild(baseName string) (child *TOCEntry, ok bool) {
	child, ok = e.children[baseName]
	return
}

func (e *TOCEntry) AddChild(baseName string, child *TOCEntry) {
	if e.children == nil {
		e.children = make(map[string]*TOCEntry)
	}
	if child.Type == "dir" {
		e.NumLink++ // Entry ".." in the subdirectory links to this directory
	}
	e.children[baseName] = child
}

func (e *TOCEntry) GetChild(baseName string) (*TOCEntry, bool) {
	if e == nil || e.children == nil {
		return nil, false
	}
	item, okay := e.children[baseName]
	return item, okay
}

func (e *TOCEntry) HasChild(baseName string) (r bool) {
	_, r = e.GetChild(baseName)
	return
}

func (e *TOCEntry) Children() map[string]*TOCEntry {
	return e.children
}

func (e *TOCEntry) RemoveChild(baseName string) {
	if e == nil || e.children == nil {
		return
	}
	item, okay := e.children[baseName]
	if !okay {
		return
	}
	if item.Type == "dir"{
		e.NumLink--
	}
	delete(e.children, baseName)
}

func (e *TOCEntry) RemoveAllChildren() {
	if e == nil || e.children == nil {
		return
	}
	for _, item := range e.children{
		if item.Type == "dir"{
			e.NumLink--
		}
	}
	for k := range e.children {
		delete(e.children, k)
	}
}

// Helper Methods

func (e *TOCEntry) SetSourceLayer(d int) {
	e.sourceLayer = d
}

func (e *TOCEntry) GetSourceLayer() int {
	return e.sourceLayer
}

// IsDataType reports whether TOCEntry is a regular file or chunk (something that
// contains regular file data).
func (e *TOCEntry) IsDataType() bool { return e.Type == "reg" || e.Type == "chunk" }

func (e *TOCEntry) IsDir() bool {
	return e.Type == "dir"
}

func (e *TOCEntry) IsMeta() bool {
	return e.Type == "meta"
}

func (e *TOCEntry) IsLandmark() bool {
	return e.Name == PrefetchLandmark || e.Name == NoPrefetchLandmark
}

func (e *TOCEntry) IsRoot() bool {
	return e.Name == "."
}

func (e *TOCEntry) HasChunk() bool {
	return e.Type == "reg" && e.ChunkSize > 0 && e.ChunkSize < e.Size
}

func (e *TOCEntry) IsWhiteoutFile() bool {
	return strings.HasPrefix(path.Base(e.Name), ".wh.")
}

// Other Operations

func (e *TOCEntry) CopyEntry() (c *TOCEntry) {
	c = &TOCEntry{
		Name:        e.Name,
		Type:        e.Type,
		Size:        e.Size,
		ModTime3339: e.ModTime3339,
		modTime:     e.modTime,
		LinkName:    e.LinkName,
		Mode:        e.Mode,
		UID:         e.UID,
		GID:         e.GID,
		Uname:       e.Uname,
		Gname:       e.Gname,
		Offset:      e.Offset,
		nextOffset:  e.nextOffset,
		DevMajor:    e.DevMajor,
		DevMinor:    e.DevMinor,
		NumLink:     e.NumLink,
		Xattrs:      e.Xattrs,
		Digest:      e.Digest,
		ChunkOffset: e.ChunkOffset,
		ChunkSize:   e.ChunkSize,
		CompressedSize: e.CompressedSize
		sourceLayer: e.sourceLayer,
		landmark:    e.landmark,
	}
	return
}

func (e *TOCEntry) UpdateMetadataFrom(s *TOCEntry) {
	e.Name = s.Name
	e.Type = s.Type
	e.Size = s.Size
	e.ModTime3339 = s.ModTime3339
	e.modTime = s.modTime

	e.LinkName = s.LinkName
	e.Mode = s.Mode
	e.UID = s.UID
	e.GID = s.GID
	e.Uname = s.Uname
	e.Gname = s.Gname

	e.DevMajor = s.DevMajor
	e.DevMinor = s.DevMinor

	e.NumLink = s.NumLink //TODO: We may need to change this later
	// Ignore Offset, nextOffset

	e.Xattrs = s.Xattrs
	e.Digest = s.Digest
	e.ChunkOffset = s.ChunkOffset
	e.ChunkSize = s.ChunkSize

	if e.landmark > s.landmark {
		e.landmark = s.landmark
	}

	// SourceLayer remains unchanged
}

func (e *TOCEntry) ToTarHeader() (h *tar.Header) {
	h = &tar.Header{Format: tar.FormatUSTAR}

	switch e.Type {
	case "hardlink":
		h.Typeflag = tar.TypeLink
		h.Linkname = e.LinkName
	case "symlink":
		h.Typeflag = tar.TypeSymlink
		h.Linkname = e.LinkName
	case "dir":
		h.Typeflag = tar.TypeDir
	case "reg":
		h.Typeflag = tar.TypeReg
		h.Size = e.Size
	case "char":
		h.Typeflag = tar.TypeChar
		h.Devmajor = int64(e.DevMajor)
		h.Devminor = int64(e.DevMinor)
	case "block":
		h.Typeflag = tar.TypeBlock
		h.Devmajor = int64(e.DevMajor)
		h.Devminor = int64(e.DevMinor)
	case "fifo":
		h.Typeflag = tar.TypeFifo
	case "chunk":
		h.Typeflag = tar.TypeReg

	}

	h.Name = e.Name
	h.Mode = e.Mode
	h.Uid = e.UID
	h.Gid = e.GID
	h.Uname = e.Uname
	h.Gname = e.Gname
	h.ModTime = e.modTime

	if len(e.Xattrs) > 0 {
		for k, v := range e.Xattrs {
			h.PAXRecords["SCHILY.xattr."+k] = string(v)
		}
	}

	return
}

func MakeEmptyFile(fileName string) (e *TOCEntry) {
	e = &TOCEntry{
		Name:        fileName,
		Type:        "reg",
		NumLink:     1,
		Digest:      EmptyFileHash,
	}
	return e
}

// MakeWhiteoutFile parent should include the trailing backslash
func MakeWhiteoutFile(baseName, parentDir string) (e *TOCEntry) {
	e = MakeEmptyFile(path.Join(parentDir, fmt.Sprintf(".wh.%s", baseName)))
	return e
}

func MakeOpaqueWhiteoutFile(parentDir string) (e *TOCEntry) {
	e = MakeEmptyFile(path.Join(parentDir, ".wh..wh..opq"))
	return e
}

func MakeDir(dirName string) (e *TOCEntry) {
	e = &TOCEntry{
		Name:    dirName,
		Type:    "dir",
		Mode:    0755,
		NumLink: 2, // The directory itself(.).
	}
	return
}

/*
TOCEntry section ends.
*/

// fileInfo implements os.FileInfo using the wrapped *TOCEntry.
type fileInfo struct{ e *TOCEntry }

var _ os.FileInfo = fileInfo{}

func (fi fileInfo) Name() string       { return path.Base(fi.e.Name) }
func (fi fileInfo) IsDir() bool        { return fi.e.Type == "dir" }
func (fi fileInfo) Size() int64        { return fi.e.Size }
func (fi fileInfo) ModTime() time.Time { return fi.e.ModTime() }
func (fi fileInfo) Sys() interface{}   { return fi.e }
func (fi fileInfo) Mode() (m os.FileMode) {
	m = os.FileMode(fi.e.Mode) & os.ModePerm
	switch fi.e.Type {
	case "dir":
		m |= os.ModeDir
	case "symlink":
		m |= os.ModeSymlink
	case "char":
		m |= os.ModeDevice | os.ModeCharDevice
	case "block":
		m |= os.ModeDevice
	case "fifo":
		m |= os.ModeNamedPipe
	}
	// TODO: ModeSetuid, ModeSetgid, if/as needed.
	return m
}

// TOCEntryVerifier holds verifiers that are usable for verifying chunks contained
// in a eStargz blob.
type TOCEntryVerifier interface {

	// Verifier provides a content verifier that can be used for verifying the
	// contents of the specified TOCEntry.
	Verifier(ce *TOCEntry) (digest.Verifier, error)
}
