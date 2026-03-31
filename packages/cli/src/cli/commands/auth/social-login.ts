import { dirname, join } from "node:path";
import { Argument, type Command } from "commander";
import type { CLIContext, RunCommandResult } from "@/cli/types.js";
import { Base44Command, resolveSecret, runTask } from "@/cli/utils/index.js";
import { InvalidInputError } from "@/core/errors.js";
import { readProjectConfig } from "@/core/project/index.js";
import type { AuthConfig } from "@/core/resources/auth-config/index.js";
import {
  DEFAULT_AUTH_CONFIG,
  hasAnyLoginMethod,
  readAuthConfig,
  writeAuthConfig,
} from "@/core/resources/auth-config/index.js";
import { setSecrets } from "@/core/resources/secret/index.js";

interface CustomOAuthSchema {
  /** AuthConfig field for the OAuth mode (e.g., "googleOAuthMode") */
  modeField: keyof AuthConfig;
  /** AuthConfig field for the client ID (e.g., "googleOAuthClientId") */
  clientIdField: keyof AuthConfig;
  /** Secret key name as expected by the backend */
  secretKey: string;
  /** Environment variable name for the client secret */
  envVar: string;
  /** Prompt message for interactive secret input */
  promptMessage: string;
}

interface SocialProviderSchema {
  /** AuthConfig boolean field to toggle (e.g., "enableGoogleLogin") */
  field: keyof AuthConfig;
  /** Display label (e.g., "Google") */
  label: string;
  /** Custom OAuth configuration, if the provider supports it */
  customOAuth?: CustomOAuthSchema;
}

const SOCIAL_PROVIDERS: Record<string, SocialProviderSchema> = {
  google: {
    field: "enableGoogleLogin",
    label: "Google",
    customOAuth: {
      modeField: "googleOAuthMode",
      clientIdField: "googleOAuthClientId",
      secretKey: "google_oauth_client_secret",
      envVar: "BASE44_GOOGLE_OAUTH_CLIENT_SECRET",
      promptMessage: "Enter Google OAuth client secret",
    },
  },
  microsoft: { field: "enableMicrosoftLogin", label: "Microsoft" },
  facebook: { field: "enableFacebookLogin", label: "Facebook" },
  apple: { field: "enableAppleLogin", label: "Apple" },
};

type ProviderName = keyof typeof SOCIAL_PROVIDERS;

const VALID_PROVIDERS = Object.keys(SOCIAL_PROVIDERS);

interface SocialLoginOptions {
  clientId?: string;
  clientSecret?: string;
  clientSecretStdin?: boolean;
}

function hasCustomOAuthOptions(options: SocialLoginOptions): boolean {
  return Boolean(
    options.clientId || options.clientSecret || options.clientSecretStdin,
  );
}

async function socialLoginAction(
  { log, isNonInteractive }: CLIContext,
  provider: ProviderName,
  action: "enable" | "disable",
  options: SocialLoginOptions,
): Promise<RunCommandResult> {
  const shouldEnable = action === "enable";
  const providerInfo = SOCIAL_PROVIDERS[provider];
  const hasOAuthOptions = hasCustomOAuthOptions(options);

  // Validate custom OAuth options against provider support
  if (hasOAuthOptions && !providerInfo.customOAuth) {
    throw new InvalidInputError(
      `Custom OAuth options are only supported for providers with custom OAuth (e.g., google). Use: base44 auth social-login ${provider} ${action}`,
    );
  }

  if (hasOAuthOptions && !shouldEnable) {
    throw new InvalidInputError(
      `Custom OAuth options cannot be used with disable. To disable ${providerInfo.label} login: base44 auth social-login ${provider} disable`,
    );
  }

  const { project } = await readProjectConfig();
  const configDir = dirname(project.configPath);
  const authDir = join(configDir, project.authDir);

  // Resolve custom OAuth secret if applicable
  const useCustomOAuth =
    shouldEnable && hasOAuthOptions && providerInfo.customOAuth;
  let clientSecret: string | undefined;

  if (useCustomOAuth) {
    const oauth = providerInfo.customOAuth!;
    clientSecret = await resolveSecret({
      flagValue: options.clientSecret,
      fromStdin: options.clientSecretStdin,
      envVar: oauth.envVar,
      promptMessage: oauth.promptMessage,
      isNonInteractive,
      name: "client secret",
      hints: [
        {
          message: `Provide via flag:   base44 auth social-login ${provider} enable --client-id <id> --client-secret <secret>`,
          command: `base44 auth social-login ${provider} enable --client-id <id> --client-secret <secret>`,
        },
        {
          message: `Provide via stdin:  echo <secret> | base44 auth social-login ${provider} enable --client-id <id> --client-secret-stdin`,
        },
        {
          message: `Provide via env:    ${oauth.envVar}=<secret> base44 auth social-login ${provider} enable --client-id <id>`,
        },
      ],
    });
  }

  // Update local auth config
  const updated = await runTask("Updating local auth config", async () => {
    const current = (await readAuthConfig(authDir)) ?? DEFAULT_AUTH_CONFIG;
    const merged: AuthConfig = {
      ...current,
      [providerInfo.field]: shouldEnable,
    };

    // Apply custom OAuth config if the provider supports it
    if (providerInfo.customOAuth) {
      const oauth = providerInfo.customOAuth;
      if (useCustomOAuth) {
        (merged as Record<string, unknown>)[oauth.modeField] = "custom";
        (merged as Record<string, unknown>)[oauth.clientIdField] =
          options.clientId!;
      } else {
        (merged as Record<string, unknown>)[oauth.modeField] = "default";
        (merged as Record<string, unknown>)[oauth.clientIdField] = null;
      }
    }

    await writeAuthConfig(authDir, merged);
    return merged;
  });

  // Push secret to API if custom OAuth
  if (clientSecret && providerInfo.customOAuth) {
    await runTask("Saving client secret", async () => {
      await setSecrets({
        [providerInfo.customOAuth!.secretKey]: clientSecret,
      });
    });
  }

  if (!shouldEnable && !hasAnyLoginMethod(updated)) {
    log.warn(
      `Disabling ${providerInfo.label} login will leave no login methods enabled. Users will be locked out.`,
    );
  }

  const newStatus = shouldEnable ? "enabled" : "disabled";
  const oauthNote = useCustomOAuth ? " with custom OAuth" : "";
  return {
    outroMessage: `${providerInfo.label} login ${newStatus}${oauthNote} in local config. Run \`base44 auth push\` or \`base44 deploy\` to apply.`,
  };
}

export function getSocialLoginCommand(): Command {
  return new Base44Command("social-login")
    .description(
      "Enable or disable social login providers (google, microsoft, facebook, apple)",
    )
    .addArgument(
      new Argument("<provider>", "social login provider").choices(
        VALID_PROVIDERS,
      ),
    )
    .addArgument(
      new Argument("<action>", "enable or disable the provider").choices([
        "enable",
        "disable",
      ]),
    )
    .option(
      "--client-id <id>",
      "custom OAuth client ID (supported providers: google)",
    )
    .option("--client-secret <secret>", "custom OAuth client secret")
    .option("--client-secret-stdin", "Read client secret from stdin")
    .action(socialLoginAction);
}
