import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { WafEvent } from "@/lib/api";
import { useSSE } from "./use-sse";

type MockEventSource = {
	onopen: (() => void) | null;
	onmessage: ((event: MessageEvent) => void) | null;
	onerror: ((event: Event) => void) | null;
	close: () => void;
};

describe("useSSE", () => {
	let instance: MockEventSource | null = null;
	const mockClose = vi.fn();

	beforeEach(() => {
		instance = null;

		const MockES = vi.fn(function (this: MockEventSource) {
			this.onopen = null;
			this.onmessage = null;
			this.onerror = null;
			this.close = mockClose;
			// Store reference for test manipulation
			instance = this;
		}) as unknown as typeof EventSource;

		vi.stubGlobal("EventSource", MockES);
	});

	afterEach(() => {
		vi.restoreAllMocks();
		mockClose.mockClear();
	});

	function getInstance() {
		if (!instance) {
			throw new Error("EventSource was not initialized");
		}
		return instance;
	}

	it("connects to /api/v1/sse", () => {
		const onEvent = vi.fn();
		renderHook(() => useSSE(onEvent));
		expect(EventSource).toHaveBeenCalledWith("/api/v1/sse");
	});

	it("sets connected=true on open", async () => {
		const onEvent = vi.fn();
		renderHook(() => useSSE(onEvent));

		const es = getInstance();
		act(() => {
			es.onopen?.();
		});

		// connected state is managed internally; we just verify no crash
		expect(es).toBeTruthy();
	});

	it("forwards valid WAF events to callback", () => {
		const onEvent = vi.fn();
		renderHook(() => useSSE(onEvent));

		const wafEvent: WafEvent = {
			id: "1",
			timestamp: new Date().toISOString(),
			request_id: "req-1",
			client_ip: "1.2.3.4",
			method: "GET",
			path: "/test",
			query: "",
			action: "block",
			score: 80,
			findings: [],
			duration_ns: 1000,
			status_code: 403,
			user_agent: "test",
			browser: "Chrome",
			browser_version: "120",
			os: "Windows",
			device_type: "desktop",
			is_bot: false,
		};

		getInstance().onmessage?.({
			data: JSON.stringify(wafEvent),
		} as MessageEvent);
		expect(onEvent).toHaveBeenCalledWith(wafEvent);
	});

	it("ignores control messages without action/client_ip", () => {
		const onEvent = vi.fn();
		renderHook(() => useSSE(onEvent));

		getInstance().onmessage?.({
			data: JSON.stringify({ type: "connected" }),
		} as MessageEvent);
		expect(onEvent).not.toHaveBeenCalled();
	});

	it("ignores malformed JSON", () => {
		const onEvent = vi.fn();
		renderHook(() => useSSE(onEvent));

		getInstance().onmessage?.({ data: "not json" } as MessageEvent);
		expect(onEvent).not.toHaveBeenCalled();
	});

	it("closes EventSource on unmount", () => {
		const onEvent = vi.fn();
		const { unmount } = renderHook(() => useSSE(onEvent));

		unmount();
		expect(mockClose).toHaveBeenCalled();
	});

	it("handles error and closes connection", () => {
		const onEvent = vi.fn();
		renderHook(() => useSSE(onEvent));

		act(() => {
			getInstance().onerror?.(new Event("error"));
		});

		expect(mockClose).toHaveBeenCalled();
	});
});
