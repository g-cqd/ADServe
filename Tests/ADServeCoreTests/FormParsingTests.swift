// M3 in-house form parsing: application/x-www-form-urlencoded + multipart/form-data (RFC 7578).

import Foundation
import HTTPTypes
import Testing

@testable import ADServeCore

@Suite struct URLEncodedFormTests {
    @Test func parsesFieldsWithDecoding() {
        let form = URLEncodedForm(Array("name=Jane+Doe&email=jane%40example.com&n=42".utf8))
        #expect(form["name"] == "Jane Doe")  // + → space
        #expect(form["email"] == "jane@example.com")  // %40 → @
        #expect(form["n"] == "42")
        #expect(form.int("n") == 42)
        #expect(form["absent"] == nil)
    }

    @Test func emptyAndBareValues() {
        let form = URLEncodedForm(Array("a=&b&c=3".utf8))
        #expect(form["a"] == "")
        #expect(form["b"] == "")  // bare key → empty value
        #expect(form["c"] == "3")
    }

    @Test func encodedPlusIsPreserved() {
        // %2B is an encoded '+', which must stay '+' (only a literal '+' maps to space).
        #expect(URLEncodedForm(Array("x=a%2Bb".utf8))["x"] == "a+b")
    }
}

@Suite struct MultipartParsingTests {
    @Test func extractsBoundaryFromContentType() {
        #expect(
            MultipartParser.boundary(fromContentType: "multipart/form-data; boundary=----abc123")
                == "----abc123")
        #expect(
            MultipartParser.boundary(fromContentType: #"multipart/form-data; boundary="quoted bound""#)
                == "quoted bound")
        #expect(MultipartParser.boundary(fromContentType: "application/json") == nil)
    }

    @Test func parsesFieldsAndAFilePart() throws {
        let boundary = "----TestBoundary"
        let crlf = "\r\n"
        let body =
            "--\(boundary)\(crlf)"
            + "Content-Disposition: form-data; name=\"username\"\(crlf)\(crlf)"
            + "jane\(crlf)"
            + "--\(boundary)\(crlf)"
            + "Content-Disposition: form-data; name=\"avatar\"; filename=\"a.txt\"\(crlf)"
            + "Content-Type: text/plain\(crlf)\(crlf)"
            + "FILE-CONTENT\(crlf)"
            + "--\(boundary)--\(crlf)"
        let form = MultipartParser.parse(Array(body.utf8), boundary: boundary)

        #expect(form.parts.count == 2)
        #expect(form["username"]?.text == "jane")
        #expect(form["username"]?.isFile == false)

        let avatar = try #require(form["avatar"])
        #expect(avatar.filename == "a.txt")
        #expect(avatar.contentType == "text/plain")
        #expect(avatar.text == "FILE-CONTENT")
        #expect(avatar.isFile)

        #expect(form.fields["username"] == "jane")
        #expect(form.files.count == 1)
        #expect(form.files.first?.name == "avatar")
    }

    @Test func handlesBinaryFileBytesIntact() {
        let boundary = "B"
        let prefix = "--\(boundary)\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.bin\"\r\n\r\n"
        let suffix = "\r\n--\(boundary)--\r\n"
        let payload: [UInt8] = [0x00, 0xFF, 0x10, 0x0D, 0x0A, 0x42]  // includes NUL + CRLF bytes
        let body = Array(prefix.utf8) + payload + Array(suffix.utf8)
        let form = MultipartParser.parse(body, boundary: boundary)
        #expect(form["f"]?.body == payload)  // exact bytes, not mangled
    }

    @Test func multipartReachableViaContextHelper() async throws {
        let boundary = "----CtxBoundary"
        let body =
            "--\(boundary)\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nhello\r\n--\(boundary)--\r\n"
        let routes = InputStubRoutes { input in
            guard
                let contentType = input.request.headers[.contentType],
                let parsed = MultipartParser.boundary(fromContentType: contentType)
                    .map({ MultipartParser.parse(input.request.body, boundary: $0) })
            else { return .plain(.badRequest, "no multipart") }
            return .raw(body: Array((parsed["q"]?.text ?? "none").utf8), contentType: "text/plain", status: .ok)
        }
        let request =
            "POST / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
            + "Content-Type: multipart/form-data; boundary=\(boundary)\r\n"
            + "Content-Length: \(body.utf8.count)\r\n\r\n\(body)"
        let response = try await Loopback.runRaw(request, routes: routes)
        #expect(response.hasSuffix("hello"))
    }
}
