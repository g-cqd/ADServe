// swift-tools-version: 6.4
import PackageDescription

// ADServe — a reusable, **persistence-agnostic** HTTP/2 + TLS server engine and a result-builder
// route DSL, extracted from the apple-docs `ad-server`. The engine (`ADServeCore`) pools
// `any PooledResource` through a type-erased `AnyConnectionPool`, so it depends on NO storage
// package — an application pins the concrete connection type at its composition root. `ADServeCore`
// also carries the in-house Model Context Protocol (MCP) JSON-RPC core; `ADServeDSL` adds the
// `@RouteBuilder`/`Server`/`Group`/`GET` surface + the MCP `Tool` DSL.
//
// Built as a LIBRARY (unlike the apple-docs root package): no `-cross-module-optimization`
// unsafe flags, so the package stays resolvable through a version-pinned SwiftPM requirement.

// Strict concurrency + explicit existentials + import-visibility tightening. All dependency-safe
// (no unsafe flags), so consumers resolve ADServe by version like any shipped library.
let strictSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .treatAllWarnings(as: .error),
    .enableUpcomingFeature("ExistentialAny"),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("InternalImportsByDefault"),
    .enableUpcomingFeature("MemberImportVisibility")
]

// Tests: strict + runtime actor data-race checks (unsafe flag → test targets only, never the library).
let testSettings: [SwiftSetting] = strictSettings + [.unsafeFlags(["-enable-actor-data-race-checks"])]

// Shipped-library settings: strict + StrictMemorySafety + Lifetimes. Every use of an unsafe construct (raw
// pointers, `withUnsafe*`, `unsafeBitCast`, C interop, …) must be explicitly marked `unsafe`; `Lifetimes`
// enables the lifetime-dependence syntax (Span / borrowing results). Both match the other AD-family kernels
// (ADFCore, ADHTMLCore, ADDBCore). Tests / dev codegen stay on `strictSettings` (unsafe scaffolding, unshipped).
let kernelSettings: [SwiftSetting] =
    strictSettings + [.strictMemorySafety(), .enableExperimentalFeature("Lifetimes")]

// Dev-only tooling is gated behind `ADSERVE_DEV` so consumers never resolve it (mirrors the sibling
// AD-family `*_DEV` convention). Provides the shared ADBuildTools lint/format plugins + DocC.
let isDev = Context.environment["ADSERVE_DEV"] != nil

// First-party dependencies resolve from a local checkout when the matching PATH env var is set,
// otherwise from the published `main` branch.
//   ADJSON_PATH        -> ADJSON (the MCP/response JSON codec). Pulls ADFoundation + ADConcurrency.
//   ADCONCURRENCY_PATH -> ADConcurrency (the `PooledResource`/`ResourcePool` pool primitive).
let adjsonDependency: Package.Dependency = {
    if let path = Context.environment["ADJSON_PATH"], !path.isEmpty {
        return .package(path: path)
    }
    return .package(url: "https://github.com/g-cqd/ADJSON.git", branch: "main")
}()
let adconcurrencyDependency: Package.Dependency = {
    if let path = Context.environment["ADCONCURRENCY_PATH"], !path.isEmpty {
        return .package(path: path)
    }
    return .package(url: "https://github.com/g-cqd/ADConcurrency.git", branch: "main")
}()
// ADFOUNDATION_PATH -> ADFCore, the canonical RFC 3986 `PercentCoding` byte kernel used to decode
// path captures + query values (and reject traversal smuggling). Already transitive via ADJSON;
// declared directly so ADServe reuses the family primitive instead of re-rolling percent-coding.
let adfoundationDependency: Package.Dependency = {
    if let path = Context.environment["ADFOUNDATION_PATH"], !path.isEmpty {
        return .package(path: path)
    }
    return .package(url: "https://github.com/g-cqd/ADFoundation.git", branch: "main")
}()
// ADMCP (the transport-agnostic MCP JSON-RPC core + `Tool` DSL) was a standalone package; it is now a
// target in THIS package (folded in), so there is no longer an ADMCP package dependency to resolve.
// ADTESTKIT_PATH -> ADTestKit, the family's deterministic-testing toolkit (AsyncEventProbe, managed
// TemporaryDirectory, seeded RNG, tags). TEST-ONLY: linked solely by the test targets, so a consumer of
// the shipped libraries never resolves it.
let adtestkitDependency: Package.Dependency = {
    if let path = Context.environment["ADTESTKIT_PATH"], !path.isEmpty {
        return .package(path: path)
    }
    return .package(url: "https://github.com/g-cqd/ADTestKit.git", branch: "main")
}()

var packageDependencies: [Package.Dependency] = [
    .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
    .package(url: "https://github.com/apple/swift-nio-extras.git", from: "1.34.1"),
    .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.37.0"),
    .package(url: "https://github.com/apple/swift-nio-http2.git", from: "1.44.0"),
    .package(url: "https://github.com/apple/swift-nio-transport-services.git", from: "1.28.0"),
    .package(url: "https://github.com/apple/swift-http-types.git", from: "1.6.0"),
    .package(url: "https://github.com/apple/swift-log.git", from: "1.13.2"),
    .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    .package(url: "https://github.com/swift-server/swift-service-lifecycle.git", from: "2.6.0"),
    // Observability (the swift-server ecosystem primitives) — used ONLY by the opt-in
    // `ADServeObservability` target, so a consumer of the bare engine/DSL never resolves them.
    .package(url: "https://github.com/apple/swift-metrics.git", from: "2.4.1"),
    .package(url: "https://github.com/apple/swift-distributed-tracing.git", from: "1.1.2"),
    .package(url: "https://github.com/apple/swift-service-context.git", from: "1.1.0"),
    adjsonDependency,
    adconcurrencyDependency,
    adfoundationDependency,
    adtestkitDependency
]
if isDev {
    if let path = Context.environment["ADBUILDTOOLS_PATH"], !path.isEmpty {
        packageDependencies.append(.package(path: path))
    } else {
        packageDependencies.append(
            .package(url: "https://github.com/g-cqd/ADBuildTools.git", branch: "main"))
    }
    packageDependencies.append(
        .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.0.0"))
    // ordo-one's statistically-rigorous benchmark framework (p-percentile latencies + throughput +
    // malloc counts), matching the sibling ADFoundation / ADJSON / ADDB suites. The suite lives in
    // `Benchmarks/ADServeSuite` and runs via `ADSERVE_DEV=1 swift package benchmark`. Dev-only, so
    // consumers of the engine/DSL never resolve it.
    packageDependencies.append(.package(url: "https://github.com/ordo-one/benchmark", from: "1.4.0"))
}

let libraryBuildPlugins: [Target.PluginUsage] =
    isDev ? [.plugin(name: "LintBuild", package: "ADBuildTools")] : []

let package = Package(
    name: "ADServe",
    // The family floor: `Synchronization` (Mutex/Atomic — the pool/readiness/in-flight counter) ships
    // in macOS 15 / iOS 18 / tvOS 18 / watchOS 11 / visionOS 2. The server itself is macOS/Linux-first.
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11),
        .visionOS(.v2)
    ],
    products: [
        // The engine: NIO bootstrap + HTTP/1.1+2 + TLS, the response envelope, and the type-erased
        // connection pool. Persistence-agnostic. `@_exported import`s the in-package ADMCP target.
        .library(name: "ADServeCore", targets: ["ADServeCore"]),
        // The route result-builder DSL over the engine's public surface (the MCP `Tool` DSL now lives
        // in ADMCP, re-exported transitively via ADServeCore).
        .library(name: "ADServeDSL", targets: ["ADServeDSL"]),
        // Opt-in observability middleware (swift-metrics + swift-distributed-tracing) — separate so
        // the bare engine stays dependency-light. A consumer adds it only if it wants the integration.
        .library(name: "ADServeObservability", targets: ["ADServeObservability"]),
        // The transport-agnostic MCP JSON-RPC core + `Tool` DSL, folded in from the former standalone
        // ADMCP package. Its own product so a consumer can use MCP (e.g. over stdio) without the HTTP
        // engine — it depends only on ADJSON / ADConcurrency / swift-log, not NIO.
        .library(name: "ADMCP", targets: ["ADMCP"])
    ],
    dependencies: packageDependencies,
    targets: [
        // ADMCP — transport-agnostic MCP JSON-RPC core + `Tool` DSL, folded in from the former
        // standalone package. Depends only on ADJSON / ADConcurrency / swift-log — NOT the NIO engine —
        // so the ADMCP product stays usable over stdio without HTTP. ADServeCore @_exported imports it.
        .target(
            name: "ADMCP",
            dependencies: [
                .product(name: "ADJSON", package: "ADJSON"),
                .product(name: "ADConcurrency", package: "ADConcurrency"),
                .product(name: "Logging", package: "swift-log")
            ],
            swiftSettings: strictSettings,
            plugins: libraryBuildPlugins),
        .target(
            name: "ADServeCore",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                // WebSockets: the HTTP/1 Upgrade + frame codec/aggregator (apple/swift-nio, already a dep).
                .product(name: "NIOWebSocket", package: "swift-nio"),
                .product(name: "NIOExtras", package: "swift-nio-extras"),
                .product(name: "NIOHTTPTypes", package: "swift-nio-extras"),
                .product(name: "NIOHTTPTypesHTTP1", package: "swift-nio-extras"),
                .product(name: "NIOHTTPTypesHTTP2", package: "swift-nio-extras"),
                // On-the-fly response compression (gzip/deflate) — already a package dep; add the product.
                .product(name: "NIOHTTPCompression", package: "swift-nio-extras"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOHTTP2", package: "swift-nio-http2"),
                .product(name: "NIOTransportServices", package: "swift-nio-transport-services"),
                .product(name: "HTTPTypes", package: "swift-http-types"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "ServiceLifecycle", package: "swift-service-lifecycle"),
                .product(name: "UnixSignals", package: "swift-service-lifecycle"),
                .product(name: "ADJSON", package: "ADJSON"),
                .product(name: "ADConcurrency", package: "ADConcurrency"),
                .product(name: "ADFCore", package: "ADFoundation"),
                "ADMCP"
            ],
            swiftSettings: kernelSettings,
            plugins: libraryBuildPlugins),
        .target(
            name: "ADServeDSL",
            dependencies: [
                "ADServeCore",
                .product(name: "ADConcurrency", package: "ADConcurrency"),
                .product(name: "ADFCore", package: "ADFoundation"),
                .product(name: "HTTPTypes", package: "swift-http-types"),
                .product(name: "ADJSON", package: "ADJSON")
            ],
            swiftSettings: kernelSettings,
            plugins: libraryBuildPlugins),
        .target(
            name: "ADServeObservability",
            dependencies: [
                "ADServeCore",
                .product(name: "HTTPTypes", package: "swift-http-types"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Metrics", package: "swift-metrics"),
                .product(name: "Tracing", package: "swift-distributed-tracing"),
                .product(name: "Instrumentation", package: "swift-distributed-tracing"),
                .product(name: "ServiceContextModule", package: "swift-service-context")
            ],
            swiftSettings: kernelSettings,
            plugins: libraryBuildPlugins),
        // Dev-only MIME-table generator — run by hand (`swift run ADServeMimeCodegen`); reads the
        // vendored jshttp/mime-db snapshot and emits the committed
        // `Sources/ADServeCore/Generated/MIMEDatabase.swift`. NOT a product, so consumers of the
        // libraries never build it. Foundation-only (no package dependency); mirrors ADHTML's
        // ADHTMLCodegen (ADR-0009): committed, reviewable output, never a build plugin.
        .executableTarget(
            name: "ADServeMimeCodegen",
            resources: [.copy("mime-db.json")],
            swiftSettings: strictSettings),
        .testTarget(
            name: "ADServeCoreTests",
            dependencies: [
                "ADServeCore",
                .product(name: "ADJSON", package: "ADJSON"),
                .product(name: "HTTPTypes", package: "swift-http-types"),
                // Loopback integration tests bind a real listener + drive a raw NIO client.
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOEmbedded", package: "swift-nio"),
                .product(name: "NIOExtras", package: "swift-nio-extras"),
                // The TLS + HTTP/2 loopback client (`.stream`/`.sse`/`.file` over h2+TLS): NIOSSL for
                // the insecure test client context, NIOHTTP2 + NIOHTTPTypesHTTP2 for the h2 stream
                // multiplexer speaking the same swift-http-types parts the engine serves.
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOHTTP2", package: "swift-nio-http2"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOWebSocket", package: "swift-nio"),
                .product(name: "NIOHTTPTypes", package: "swift-nio-extras"),
                .product(name: "NIOHTTPTypesHTTP2", package: "swift-nio-extras"),
                // Deterministic-testing toolkit: AsyncEventProbe (wait-or-throw, no polling), managed
                // temp dirs — replacing ad-hoc `Flag`+poll loops in the timing-sensitive integration tests.
                .product(name: "ADTestKit", package: "ADTestKit")
            ],
            swiftSettings: testSettings),
        .testTarget(
            name: "ADServeDSLTests",
            dependencies: [
                "ADServeDSL", "ADServeCore",
                .product(name: "HTTPTypes", package: "swift-http-types"),
                .product(name: "ADJSON", package: "ADJSON")
            ],
            swiftSettings: testSettings),
        .testTarget(
            name: "ADServeObservabilityTests",
            dependencies: [
                "ADServeObservability", "ADServeCore",
                .product(name: "HTTPTypes", package: "swift-http-types"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Metrics", package: "swift-metrics"),
                .product(name: "MetricsTestKit", package: "swift-metrics"),
                .product(name: "Tracing", package: "swift-distributed-tracing"),
                .product(name: "Instrumentation", package: "swift-distributed-tracing"),
                .product(name: "InMemoryTracing", package: "swift-distributed-tracing"),
                .product(name: "ServiceContextModule", package: "swift-service-context")
            ],
            swiftSettings: testSettings),
        // Folded in from the former standalone ADMCP package.
        .testTarget(
            name: "ADMCPTests",
            dependencies: [
                "ADMCP",
                .product(name: "ADJSON", package: "ADJSON"),
                .product(name: "ADConcurrency", package: "ADConcurrency"),
                .product(name: "Logging", package: "swift-log")
            ],
            swiftSettings: testSettings)
    ]
)

// ordo-one benchmark suite (ADSERVE_DEV-gated): tracks `.mallocCountTotal` on the hot request/response
// header paths (cookie parse + Set-Cookie serialize) so a reintroduced allocation trips the threshold
// instead of rotting silently. Runs via `ADSERVE_DEV=1 swift package benchmark`. Mirrors ADFoundation's
// `Benchmarks/ADFoundationSuite` wiring; dev-only so consumers of the engine never resolve ordo-one.
if isDev {
    package.targets.append(
        .executableTarget(
            name: "ADServeSuite",
            dependencies: [
                "ADServeCore",
                // The route DSL (`Server`/`App`/`GET` → `RouteTable.match`) lives in ADServeDSL, and the
                // percent-coding kernel the path/query surface decodes through is `ADFCore.PercentCoding` —
                // both benchmarked here against their PUBLIC API, so the suite covers the routing + decode
                // hot paths, not just the cookie pair the original two cases tracked.
                "ADServeDSL",
                .product(name: "ADFCore", package: "ADFoundation"),
                .product(name: "Benchmark", package: "benchmark")
            ],
            path: "Benchmarks/ADServeSuite",
            swiftSettings: strictSettings,
            plugins: [.plugin(name: "BenchmarkPlugin", package: "benchmark")]))
}
