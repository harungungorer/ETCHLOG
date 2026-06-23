import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import App from './App';

vi.mock('./api/etchlog');
import * as api from './api/etchlog';

describe('App (dashboard shell)', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    // Empty log: tree_size 0. (root bytes are unused by the UI when tree_size is 0.)
    (api.getSth as Mock).mockResolvedValue({
      treeSize: 0,
      rootHash: new Uint8Array(32),
      timestamp: 1750000000000,
      signature: new Uint8Array(64),
    });
  });

  it('renders the header and tagline', async () => {
    render(<App />);
    expect(screen.getByRole('heading', { name: /Etchlog Verification Dashboard/i })).toBeTruthy();
    await waitFor(() => expect(screen.getByText(/tree_size = 0/)).toBeTruthy());
  });

  it('shows the empty-tree placeholder when there are no entries', async () => {
    render(<App />);
    await waitFor(() =>
      expect(screen.getByText(/No entries yet — append one to grow the tree/i)).toBeTruthy(),
    );
  });

  it('disables Verify inclusion until a leaf is selected', async () => {
    render(<App />);
    const verifyBtn = await screen.findByRole('button', { name: /Verify inclusion/i });
    expect((verifyBtn as HTMLButtonElement).disabled).toBe(true);
  });
});
