import ADJSON
import ADServeCore
import ADServeDSL
import HTTPCore
import Testing

@Schemable
private struct ItemDTO: Codable {
    let id: Int
    let title: String
    let price: Double
}

struct OpenAPITests {
    private func spec() -> String {
        let api = Server {
            App(pool: .none) {
                GET("items/{id}", pool: .none) { _, params in .plain(.ok, params.id ?? "") }
                    .summary("Get an item").tags("items").responds(ItemDTO.self)
                POST("items", pool: .none) { _ in .noContent }
                    .summary("Create an item").operationId("createItem").tags("items")
                    .body(ItemDTO.self).responds(ItemDTO.self, status: 201)
                GET("health", pool: .none) { _ in .plain(.ok, "ok") }  // undocumented, still in the doc
            }
        }
        return OpenAPI.document(info: OpenAPIInfo(title: "Items API", version: "1.0.0"), from: api)
    }

    @Test
    func `emits a well-formed JSON document (parses cleanly via ADJSON)`() throws {
        _ = try JSONValue(parsing: spec())  // throws on malformed JSON — the core correctness gate
    }

    @Test
    func `carries version, info, and every route's path + verb`() {
        let doc = spec()
        #expect(doc.contains(#""openapi":"3.1.0""#))
        #expect(doc.contains(#""title":"Items API""#))
        #expect(doc.contains(#""version":"1.0.0""#))
        #expect(doc.contains("/items/{id}"))
        #expect(doc.contains("/items"))
        #expect(doc.contains("/health"))  // undocumented route still contributes its path+verb
        #expect(doc.contains(#""get":{"#))
        #expect(doc.contains(#""post":{"#))
    }

    @Test
    func `derives a path parameter from the {id} segment`() {
        let doc = spec()
        #expect(doc.contains(#""parameters":["#))
        #expect(doc.contains(#""name":"id""#))
        #expect(doc.contains(#""in":"path""#))
        #expect(doc.contains(#""required":true"#))
    }

    @Test
    func `carries operation metadata: summary, tags, operationId`() {
        let doc = spec()
        #expect(doc.contains(#""summary":"Get an item""#))
        #expect(doc.contains(#""summary":"Create an item""#))
        #expect(doc.contains(#""operationId":"createItem""#))
        #expect(doc.contains(#""tags":["items"]"#))
    }

    @Test
    func `references @Schemable bodies and emits their schema into components`() {
        let doc = spec()
        #expect(doc.contains(#""requestBody":"#))
        #expect(doc.contains(##""$ref":"#/components/schemas/ItemDTO""##))
        #expect(doc.contains(#""components":{"schemas":{"ItemDTO":"#))
        // The embedded @Schemable schema carries the DTO's properties.
        #expect(doc.contains("price"))
        #expect(doc.contains("title"))
        #expect(doc.contains(#""201":"#))  // the documented 201 response
    }
}
