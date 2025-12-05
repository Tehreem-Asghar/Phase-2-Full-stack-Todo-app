// frontend/lib/error-logger.ts

/**
 * A simple error logger for the frontend.
 * In a real-world application, this would integrate with a logging service like Sentry.
 *
 * @param error - The error object to log.
 * @param context - Additional context about where the error occurred.
 */
export const logError = (error: any, context: Record<string, any> = {}) => {
  console.error("An error occurred:", {
    error: error.message || "Unknown error",
    stack: error.stack,
    ...context,
  });

  // Example of how you would send the error to a logging service:
  // if (process.env.NODE_ENV === "production") {
  //   Sentry.captureException(error, { extra: context });
  // }
};
