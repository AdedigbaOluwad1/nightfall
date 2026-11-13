import { useEffect, useRef, useState } from "react";
import {
  emptyReceipts,
  type Receipts,
  reduceReceipts,
  type TraceItem,
  type WsMessage,
} from "./events";

export type Status = "connecting" | "open" | "closed";

export interface SocketState {
  status: Status;
  trace: TraceItem[];
  receipts: Receipts;
}

export function useNightfallSocket(url: string): SocketState {
  const [status, setStatus] = useState<Status>("connecting");
  const [trace, setTrace] = useState<TraceItem[]>([]);
  const [receipts, setReceipts] = useState<Receipts>(emptyReceipts());
  const seq = useRef(0);

  useEffect(() => {
    let socket: WebSocket | undefined;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let closed = false;

    const connect = () => {
      setStatus("connecting");
      socket = new WebSocket(url);

      socket.onopen = () => setStatus("open");

      socket.onmessage = (ev) => {
        let msg: WsMessage;
        try {
          msg = JSON.parse(ev.data as string) as WsMessage;
        } catch {
          return;
        }
        const item: TraceItem = { seq: seq.current++, type: msg.type, payload: msg.payload };
        setTrace((prev) => [...prev, item]);
        setReceipts((prev) => reduceReceipts(prev, item));
      };

      socket.onclose = () => {
        setStatus("closed");
        if (!closed) retry = setTimeout(connect, 1500);
      };

      socket.onerror = () => socket?.close();
    };

    connect();
    return () => {
      closed = true;
      if (retry) clearTimeout(retry);
      socket?.close();
    };
  }, [url]);

  return { status, trace, receipts };
}
