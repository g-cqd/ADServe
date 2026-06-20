import Testing

@testable import ADServeCore

@Suite struct MediaTypeTableTests {
    @Test func fileExtensionMapsKnownTypesWithTheCharsetPolicy() {
        #expect(MediaType(fileExtension: "html")?.value == "text/html; charset=utf-8")
        #expect(MediaType(fileExtension: "css")?.value == "text/css; charset=utf-8")
        #expect(MediaType(fileExtension: "js")?.value == "text/javascript; charset=utf-8")
        #expect(MediaType(fileExtension: "JSON")?.value == "application/json; charset=utf-8")  // case-insensitive
        #expect(MediaType(fileExtension: "svg")?.value == "image/svg+xml")  // no charset (not text/*)
        #expect(MediaType(fileExtension: "wasm")?.value == "application/wasm")
        #expect(MediaType(fileExtension: "png")?.value == "image/png")
    }

    @Test func unknownExtensionIsNil() {
        #expect(MediaType(fileExtension: "nope") == nil)
        #expect(MediaType(fileExtension: "") == nil)
    }

    @Test func pathInitUsesTheFinalSegmentExtension() {
        #expect(MediaType(path: "/assets/app.min.css")?.value == "text/css; charset=utf-8")
        #expect(MediaType(path: "runtime.js")?.value == "text/javascript; charset=utf-8")
        #expect(MediaType(path: "/no/extension/here") == nil)
        #expect(MediaType(path: "/dir.with.dots/file") == nil)  // a dot in a directory, not the file
        #expect(MediaType(path: "/.env") == nil)  // leading-dot dotfile
    }

    @Test func fileExtensionHelperLowercasesAndRejectsDotfiles() {
        #expect(MediaType.fileExtension(of: "a/b/c.PNG") == "png")
        #expect(MediaType.fileExtension(of: "noext") == nil)
        #expect(MediaType.fileExtension(of: ".gitignore") == nil)
    }

    @Test func presetsDoNotDriftFromTheAuthoritativeTable() {
        #expect(MediaType.css.value == MediaType(fileExtension: "css")?.value)
        #expect(MediaType.html.value == MediaType(fileExtension: "html")?.value)
    }

    @Test func generatedTableHasRealCoverageAndTheCompressibilityFlagsB2NeedsAreSane() {
        #expect(MIMEDatabase.entry(forExtension: "pdf")?.type == "application/pdf")  // a real table, not a stub
        #expect(MIMEDatabase.entry(forExtension: "html")?.compressible == true)
        #expect(MIMEDatabase.entry(forExtension: "wasm")?.compressible == true)
        #expect(MIMEDatabase.entry(forExtension: "png")?.compressible == false)  // already compressed
        #expect(MIMEDatabase.entry(forExtension: "woff2")?.compressible == false)
        #expect(MIMEDatabase.entry(forExtension: "nope-not-real") == nil)
    }
}
