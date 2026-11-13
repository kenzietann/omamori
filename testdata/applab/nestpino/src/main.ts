// The same NestJS API with nestjs-pino, the most used JSON logger for NestJS: one JSON line for each request.
// NestJS service usually does.
import "reflect-metadata";
import { Body, Controller, Get, HttpException, Logger, Module, Post, Query, Req } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import { LoggerModule, Logger as PinoLogger } from "nestjs-pino";
import { Request } from "express";

@Controller()
class AuthController {
  private readonly logger = new Logger("AuthService");
  @Post("auth/login")
  login(@Body() body: any, @Req() request: Request) {
    if (body?.username === "alice" && body?.password === "Summer2026!") return { token: "t" };
    this.logger.warn(`Failed login for ${body?.username} from ${request.ip}`);
    throw new HttpException("invalid credentials", 401);
  }
  @Get("api/items")
  items(@Query("id") id: string) {
    if (String(id).includes("'")) {
      this.logger.error(`QueryFailedError: syntax error at or near "${id}"`);
      throw new HttpException("server error", 500);
    }
    return [];
  }
}

@Module({ imports: [LoggerModule.forRoot()], controllers: [AuthController] })
class AppModule {}

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bufferLogs: true });
  app.useLogger(app.get(PinoLogger));
  await app.listen(8080);
}
bootstrap();
