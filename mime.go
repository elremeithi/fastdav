package main

import "mime"

// The container is FROM scratch (no /etc/mime.types), so register the
// common types clients care about (previews, streaming, Office).
func init() {
	for ext, t := range map[string]string{
		".txt": "text/plain; charset=utf-8", ".md": "text/markdown; charset=utf-8", ".csv": "text/csv; charset=utf-8",
		".log": "text/plain; charset=utf-8", ".ics": "text/calendar", ".vcf": "text/vcard",
		".mp4": "video/mp4", ".m4v": "video/x-m4v", ".mkv": "video/x-matroska", ".webm": "video/webm",
		".mov": "video/quicktime", ".avi": "video/x-msvideo", ".ts": "video/mp2t", ".m3u8": "application/vnd.apple.mpegurl",
		".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".flac": "audio/flac", ".ogg": "audio/ogg", ".opus": "audio/opus",
		".wav": "audio/wav", ".aac": "audio/aac",
		".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".gif": "image/gif", ".webp": "image/webp",
		".heic": "image/heic", ".heif": "image/heif", ".avif": "image/avif", ".tif": "image/tiff", ".tiff": "image/tiff",
		".bmp": "image/bmp", ".ico": "image/x-icon", ".svg": "image/svg+xml",
		".pdf": "application/pdf", ".zip": "application/zip", ".7z": "application/x-7z-compressed",
		".gz": "application/gzip", ".tar": "application/x-tar", ".rar": "application/vnd.rar", ".iso": "application/x-iso9660-image",
		".json": "application/json", ".xml": "application/xml", ".epub": "application/epub+zip",
		".doc": "application/msword", ".xls": "application/vnd.ms-excel", ".ppt": "application/vnd.ms-powerpoint",
		".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
		".odt":  "application/vnd.oasis.opendocument.text", ".ods": "application/vnd.oasis.opendocument.spreadsheet",
		".odp": "application/vnd.oasis.opendocument.presentation", ".kdbx": "application/x-keepass2",
	} {
		_ = mime.AddExtensionType(ext, t)
	}
}
