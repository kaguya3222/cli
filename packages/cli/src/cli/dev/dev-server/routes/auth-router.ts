import { randomInt } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Request } from "express";
import { json, Router } from "express";
import jwt from "jsonwebtoken";
import { nanoid } from "nanoid";
import * as z from "zod";
import { theme } from "@/cli/utils/theme";
import { TMP_DIR } from "@/core/consts.js";
import type { DevLogger } from "../../createDevLogger.js";
import { type Database, USER_COLLECTION } from "../db/database.js";
import { getNowISOTimestamp } from "../utils.js";

const LOCAL_DEV_SECRET = "LOCAL_DEV_SECRET";

const emailToFilename = (email: string) => {
  return `${email.replace("@", "_at_").replace(".", "-")}.json`;
};

const generateCode = () => {
  return randomInt(100000, 1000000).toString();
};

const createJwtToken = (email: string) => {
  return jwt.sign({ sub: email }, LOCAL_DEV_SECRET, {
    expiresIn: "360d",
  });
};

const OtpRegiterSchema = z.object({
  id: z.string(),
  email: z.email(),
  otpCode: z.string().length(6),
  createdAt: z.number().min(1),
});

type OtpRegiter = z.infer<typeof OtpRegiterSchema>;

export function createAuthRouter(
  cwd: string,
  db: Database,
  logger: DevLogger,
): Router {
  const router = Router({ mergeParams: true });
  const parseBody = json();
  const tmpDir = join(cwd, TMP_DIR, "register");

  router.post("/login", parseBody, async (req, res) => {
    const { email, password: _password } = req.body;

    const result = await db
      .getCollection(USER_COLLECTION)
      ?.findOneAsync({ email });

    if (result) {
      res.json({
        access_token: createJwtToken(email),
        success: true,
        user: {},
      });

      return;
    }

    res.status(401).json({ error: "Unauthorized" });
  });

  router.post("/register", parseBody, async (req, res) => {
    const { email, password } = req.body;

    if ((password || "").length < 8) {
      res.status(400).json({
        detail: "Password must be at least 8 characters long",
        error_type: "HTTPException",
        message: "Password must be at least 8 characters long",
        request_id: null,
        traceback: "",
      });

      return;
    }

    const result = await db
      .getCollection(USER_COLLECTION)
      ?.findOneAsync({ email });

    if (result) {
      res.status(400).json({
        detail: "A user with this email already exists",
        error_type: "HTTPException",
        message: "A user with this email already exists",
        request_id: null,
        traceback: "",
      });
      return;
    }

    await mkdir(tmpDir, { recursive: true });

    const otpCode = generateCode();
    const id = nanoid();
    const data: OtpRegiter = {
      id,
      email,
      otpCode,
      createdAt: +Date.now(),
    };

    await writeFile(
      join(tmpDir, emailToFilename(email)),
      JSON.stringify(data, null, 2),
      {
        encoding: "utf8",
      },
    );

    logger.log(
      theme.styles.info(
        `\nIn order to complete registration use this verification code: ${otpCode}\n`,
      ),
    );

    res.json({
      id,
      message:
        "Registration successful. Please check your email for the verification code.",
      otp_expires_in_minutes: 10,
    });
  });

  router.post(
    "/verify-otp",
    parseBody,
    async (req: Request<{ appId: string }>, res) => {
      const { email, otp_code } = req.body;

      try {
        const dataStr = await readFile(join(tmpDir, emailToFilename(email)), {
          encoding: "utf8",
        });

        const data = OtpRegiterSchema.parse(JSON.parse(dataStr));

        if (
          data.otpCode === otp_code &&
          +Date.now() - data.createdAt < 10 * 60 * 1000
        ) {
          const collection = db.getCollection(USER_COLLECTION);
          const now = getNowISOTimestamp();
          const match = /^([^@]+)/.exec(email);
          if (match) {
            await collection?.insertAsync({
              id: data.id,
              email: email,
              full_name: match[1],
              is_service: false,
              is_verified: true,
              disabled: null,
              role: "user",
              collaborator_role: "editor",
              created_date: now,
              updated_date: now,
            });
          }
          res.json({
            id: data.id,
            access_token: createJwtToken(email),
            message: "Email verified successfully. You are now logged in.",
            success: true,
          });
        }

        return;
      } catch {
        const appId = req.params.appId;
        res.status(500).json({
          detail: `{'email': '${email}', 'app_id': '${appId}}'} -> Object not found`,
          error_type: "ObjectNotFoundError",
          message: `{'email': '${email}', 'app_id': '${appId}}'} -> Object not found`,
          request_id: null,
          traceback: "",
        });
        return;
      }
    },
  );

  return router;
}
