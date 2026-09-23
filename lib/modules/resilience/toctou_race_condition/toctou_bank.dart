/// TOCTOU (time-of-check to time-of-use) helper.
///
/// INTENTIONALLY VULNERABLE (CWE-367): authorization/eligibility is checked and
/// then used with a mutable gap in between, so an attacker who changes state
/// during the gap wins the race. Here a withdrawal checks the balance, yields,
/// and then debits, allowing a concurrent second withdrawal to double-spend.
///
/// The gap is made explicit (an injectable callback) so a unit test can
/// deterministically win the race and assert the balance goes negative.
class ToctouBank {
  ToctouBank(this.balance);

  int balance;

  /// Withdraws [amount] with a check-then-use gap. [duringGap] runs AFTER the
  /// balance check but BEFORE the debit, exactly where a racing request lands.
  bool withdraw(int amount, {void Function()? duringGap}) {
    // TIME OF CHECK
    final allowed = balance >= amount;
    // ---- attacker's concurrent action executes in this window ----
    if (duringGap != null) duringGap();
    // TIME OF USE (stale decision)
    if (allowed) {
      balance -= amount; // may push balance negative if state changed
      return true;
    }
    return false;
  }
}
