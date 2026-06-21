function App() {
  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex flex-col">
      <header className="border-b border-gray-800 px-6 py-4">
        <h1 className="text-xl font-semibold tracking-tight text-white">
          Etchlog Verification Dashboard
        </h1>
      </header>

      <main className="flex-1 flex items-center justify-center px-6">
        <div className="max-w-lg text-center space-y-4">
          <p className="text-gray-400 text-sm leading-relaxed">
            The in-browser Merkle-proof verifier ships in a later milestone.
            This page is a scaffold placeholder.
          </p>
          <div className="inline-block rounded border border-gray-700 bg-gray-900 px-4 py-2 text-xs font-mono text-gray-500">
            milestone 0 — scaffolding only
          </div>
        </div>
      </main>
    </div>
  )
}

export default App
