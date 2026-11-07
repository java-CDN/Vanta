import { Component, type ReactNode } from 'react';

/** Keeps one broken screen from blanking the whole window. */
export class ErrorBoundary extends Component<{ children: ReactNode; resetKey: string }, { err: Error | null; key: string }> {
  state = { err: null as Error | null, key: this.props.resetKey };
  static getDerivedStateFromError(err: Error) { return { err }; }
  static getDerivedStateFromProps(p: { resetKey: string }, s: { err: Error | null; key: string }) {
    return p.resetKey !== s.key ? { err: null, key: p.resetKey } : null;
  }
  render() {
    if (this.state.err) {
      return <main className="main"><div className="hd"><div><h1>Something went wrong</h1><div className="sub">This screen hit an error. Other screens still work.</div></div></div>
        <div className="content"><div className="card"><div className="mono dim">{this.state.err.message}</div></div></div></main>;
    }
    return this.props.children;
  }
}
