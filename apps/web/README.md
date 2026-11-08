# Nightfall web view (deferred — day 11+)

Projected demo view: vite + react, fed by a `ws` socket the CLI exposes via
`nightfall serve`. Subscribes to the same `@nightfall/core` event types.
Trace on the left; Bifrost/Tavily/scope "receipts" gauges on the right.
Do not build until the core loop reliably completes a cold run.
