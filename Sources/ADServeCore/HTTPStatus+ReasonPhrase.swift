// RFC 9110 §15 reason phrases for the registered codes ADServe names (problem titles, `HTTPError`
// descriptions, OpenAPI response summaries). Presentation-only: HTTP/2+ carry no reason phrase on
// the wire, and HTTPCore deliberately omits them from its status type — defined once here.

public import HTTPCore

extension HTTPStatus {
    /// The RFC 9110 §15 reason phrase for the registered codes ADServe names (problem titles,
    /// `HTTPError` descriptions, OpenAPI response summaries), or `"Status \(code)"` for an
    /// unregistered code. Presentation-only: HTTP/2+ carry no reason phrase on the wire.
    public var reasonPhrase: String {
        switch code {
            case 100: return "Continue"
            case 101: return "Switching Protocols"
            case 200: return "OK"
            case 201: return "Created"
            case 202: return "Accepted"
            case 204: return "No Content"
            case 206: return "Partial Content"
            case 301: return "Moved Permanently"
            case 302: return "Found"
            case 303: return "See Other"
            case 304: return "Not Modified"
            case 308: return "Permanent Redirect"
            case 400: return "Bad Request"
            case 401: return "Unauthorized"
            case 403: return "Forbidden"
            case 404: return "Not Found"
            case 405: return "Method Not Allowed"
            case 408: return "Request Timeout"
            case 409: return "Conflict"
            case 412: return "Precondition Failed"
            case 413: return "Content Too Large"
            case 414: return "URI Too Long"
            case 415: return "Unsupported Media Type"
            case 416: return "Range Not Satisfiable"
            case 417: return "Expectation Failed"
            case 422: return "Unprocessable Content"
            case 426: return "Upgrade Required"
            case 429: return "Too Many Requests"
            case 431: return "Request Header Fields Too Large"
            case 500: return "Internal Server Error"
            case 501: return "Not Implemented"
            case 502: return "Bad Gateway"
            case 503: return "Service Unavailable"
            case 504: return "Gateway Timeout"
            case 505: return "HTTP Version Not Supported"
            default: return "Status \(code)"
        }
    }
}
