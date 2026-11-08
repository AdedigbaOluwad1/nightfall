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
  get cap() {
    return this.capUsd;
  }
  get total() {
    return this.spent;
  }
}
