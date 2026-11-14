export class BudgetExceededError extends Error {
  constructor(
    readonly capUsd: number,
    readonly spentUsd: number,
  ) {
    super(`budget cap $${capUsd} reached (spent $${spentUsd.toFixed(4)})`);
    this.name = "BudgetExceededError";
  }
}

export class Budget {
  private spent = 0;
  constructor(private readonly capUsd: number) {}
  add(usd: number) {
    this.spent += usd;
  }
  assertUnder() {
    if (this.spent >= this.capUsd) {
      throw new BudgetExceededError(this.capUsd, this.spent);
    }
  }

  /**
   * Reserve check: refuse a call whose worst-case cost would push spend to/over
   * the cap, BEFORE it is made. This bounds overshoot to zero — the call that
   * would cross the line is never issued — rather than catching it after the fact
   * (a soft cap that could overshoot by one in-flight call). `estUsd <= 0` (e.g.
   * a free local model) degrades to the plain `assertUnder` behaviour.
   */
  assertCanAfford(estUsd: number) {
    const reserve = Number.isFinite(estUsd) && estUsd > 0 ? estUsd : 0;
    if (this.spent + reserve >= this.capUsd) {
      throw new BudgetExceededError(this.capUsd, this.spent);
    }
  }
  get cap() {
    return this.capUsd;
  }
  get total() {
    return this.spent;
  }
}
