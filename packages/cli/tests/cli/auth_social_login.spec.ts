import { describe, it } from "vitest";
import { fixture, setupCLITests } from "./testkit/index.js";

describe("auth social-login command", () => {
  const t = setupCLITests();

  it("fails when no arguments are provided", async () => {
    await t.givenLoggedInWithProject(fixture("basic"));

    const result = await t.run("auth", "social-login");

    t.expectResult(result).toFail();
    t.expectResult(result).toContain("missing required argument");
  });

  it("fails when no action argument is provided", async () => {
    await t.givenLoggedInWithProject(fixture("basic"));

    const result = await t.run("auth", "social-login", "google");

    t.expectResult(result).toFail();
    t.expectResult(result).toContain("missing required argument");
  });

  it("fails with invalid provider", async () => {
    await t.givenLoggedInWithProject(fixture("basic"));

    const result = await t.run("auth", "social-login", "github", "enable");

    t.expectResult(result).toFail();
    t.expectResult(result).toContain("google");
    t.expectResult(result).toContain("microsoft");
    t.expectResult(result).toContain("facebook");
    t.expectResult(result).toContain("apple");
  });

  it("fails with invalid action", async () => {
    await t.givenLoggedInWithProject(fixture("basic"));

    const result = await t.run("auth", "social-login", "google", "invalid");

    t.expectResult(result).toFail();
    t.expectResult(result).toContain("enable");
    t.expectResult(result).toContain("disable");
  });

  it("fails when not in a project directory", async () => {
    await t.givenLoggedIn({ email: "test@example.com", name: "Test User" });

    const result = await t.run("auth", "social-login", "google", "enable");

    t.expectResult(result).toFail();
    t.expectResult(result).toContain("No Base44 project found");
  });

  it("shows help with --help flag", async () => {
    const result = await t.run("auth", "social-login", "--help");

    t.expectResult(result).toSucceed();
    t.expectResult(result).toContain("social login providers");
  });

  it("shows social-login in auth subcommands", async () => {
    const result = await t.run("auth", "--help");

    t.expectResult(result).toSucceed();
    t.expectResult(result).toContain("social-login");
  });

  it("rejects custom OAuth options for non-google providers", async () => {
    await t.givenLoggedInWithProject(fixture("basic"));

    const result = await t.run(
      "auth",
      "social-login",
      "microsoft",
      "enable",
      "--client-id",
      "xxx",
    );

    t.expectResult(result).toFail();
    t.expectResult(result).toContain(
      "only supported for providers with custom OAuth",
    );
  });

  it("rejects custom OAuth options when disabling google", async () => {
    await t.givenLoggedInWithProject(fixture("basic"));

    const result = await t.run(
      "auth",
      "social-login",
      "google",
      "disable",
      "--client-id",
      "xxx",
    );

    t.expectResult(result).toFail();
    t.expectResult(result).toContain("cannot be used with disable");
  });

  it("shows Google OAuth options in help", async () => {
    const result = await t.run("auth", "social-login", "--help");

    t.expectResult(result).toSucceed();
    t.expectResult(result).toContain("--client-id");
    t.expectResult(result).toContain("--client-secret");
    t.expectResult(result).toContain("--client-secret-stdin");
  });
});
