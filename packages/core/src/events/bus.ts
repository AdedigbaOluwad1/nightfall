import Emittery from "emittery";
import type { NightfallEvents } from "./types.js";

/** The single shared event bus. Import `bus` everywhere; never log directly. */
export const bus = new Emittery<NightfallEvents>();
export type Bus = typeof bus;
