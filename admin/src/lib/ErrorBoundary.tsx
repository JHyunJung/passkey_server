import { Component, type ErrorInfo, type ReactNode } from "react";
import { captureException } from "@/lib/sentry";

/**
 * App-level fatal error boundary. Owns no Sentry import itself — it reports through the buffered
 * {@link captureException}, which keeps `@sentry/react` off the first-paint critical path
 * (bundle-defer-third-party). Errors thrown before the Sentry chunk resolves are queued and
 * flushed once it loads, so nothing is lost during the gap.
 */
interface Props {
  fallback: (args: { resetError: () => void }) => ReactNode;
  children: ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    captureException(error, {
      // componentStack is the React tree path to the throwing component — invaluable for triage.
      extra: { componentStack: info.componentStack },
    });
  }

  private resetError = () => {
    this.setState({ error: null });
  };

  render() {
    if (this.state.error) {
      return this.props.fallback({ resetError: this.resetError });
    }
    return this.props.children;
  }
}
