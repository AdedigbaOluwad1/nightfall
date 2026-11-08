export class Budget {
  private spent = 0;
  constructor(private readonly capUsd: number) {}
  add(usd: number) {
    this.spent += usd;
  }
  assertUnder() {
    if (this.spent >= this.capUsd) {
      throw new Error(`budget cap $${this.capUsd} reached (spent $${this.spent.toFixed(4)})`);
    }
  }
  get total() {
    return this.spent;
  }
}
