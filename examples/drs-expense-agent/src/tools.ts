/**
 * Real expense tool implementations.
 *
 * These functions do actual file I/O — no mock data, no hard-coded returns.
 *
 * DRS policy enforcement is NOT done here. The agent records what it did in
 * the invocation receipt's args field. The drs-verify Go server independently
 * checks whether those args violate the delegation policy (Block D1). This
 * separation is the core DRS design: the tool executes, the verifier audits.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

export interface Expense {
  id: string;
  vendor: string;
  amount: number;
  category: string;
  date: string;
  description: string;
  status: string;
}

const EXPENSES_PATH = resolve(process.cwd(), "data/expenses.json");

/**
 * Reads all expense records from disk.
 * Returns the parsed array — no filtering, no transformation.
 */
export function readExpenses(): Expense[] {
  const raw = readFileSync(EXPENSES_PATH, "utf-8");
  return JSON.parse(raw) as Expense[];
}

/**
 * Updates the category field of a specific expense record and writes back to disk.
 * Returns a result object describing what happened.
 */
export function categorizeTransaction(
  id: string,
  category: string,
): { success: boolean; message: string } {
  const expenses = readExpenses();
  const expense = expenses.find((e) => e.id === id);
  if (!expense) {
    return { success: false, message: `Transaction ${id} not found.` };
  }
  expense.category = category;
  writeFileSync(EXPENSES_PATH, JSON.stringify(expenses, null, 2), "utf-8");
  return {
    success: true,
    message: `Transaction ${id} categorized as "${category}".`,
  };
}

/**
 * Returns the expense record for payment approval.
 *
 * Important: this function does NOT check the DRS policy. It returns the
 * amount unconditionally. The agent will include estimated_cost_usd in the
 * invocation receipt args, and drs-verify will check it against max_cost_usd
 * from the delegation. If amount > 500, the Go server returns POLICY_VIOLATION.
 */
export function approvePayment(id: string): {
  success: boolean;
  amount: number;
  message: string;
} {
  const expenses = readExpenses();
  const expense = expenses.find((e) => e.id === id);
  if (!expense) {
    return { success: false, amount: 0, message: `Transaction ${id} not found.` };
  }
  return {
    success: true,
    amount: expense.amount,
    message: `Payment of $${expense.amount.toFixed(2)} to ${expense.vendor} submitted for approval.`,
  };
}
