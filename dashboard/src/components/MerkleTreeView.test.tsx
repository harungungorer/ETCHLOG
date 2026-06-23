import { render, screen, fireEvent } from '@testing-library/react';
import { MerkleTreeView } from './MerkleTreeView';
import type { TreeNode } from '../verifier/merkle';

// ─── Hand-built TreeNode fixtures (no crypto needed) ────────────────────────

function makeLeaf(leafIndex: number, hashHex: string): TreeNode {
  return {
    hash: new Uint8Array(32).fill(leafIndex),
    hashHex,
    isLeaf: true,
    leafIndex,
    lo: leafIndex,
    hi: leafIndex + 1,
  };
}

function makeInterior(
  lo: number,
  hi: number,
  hashHex: string,
  left: TreeNode,
  right: TreeNode,
): TreeNode {
  return {
    hash: new Uint8Array(32).fill(lo + 10),
    hashHex,
    isLeaf: false,
    leafIndex: -1,
    lo,
    hi,
    left,
    right,
  };
}

// A minimal 2-leaf tree:
//       root
//      /    \
//   leaf0  leaf1
const LEAF0_HEX = 'aabbcc001122000000000000000000000000000000000000000000000000000000';
const LEAF1_HEX = 'ddeeff334455000000000000000000000000000000000000000000000000000000';
const ROOT_HEX  = 'ffffffff000000000000000000000000000000000000000000000000000000ff';

const leaf0 = makeLeaf(0, LEAF0_HEX);
const leaf1 = makeLeaf(1, LEAF1_HEX);
const twoLeafRoot = makeInterior(0, 2, ROOT_HEX, leaf0, leaf1);

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('MerkleTreeView', () => {
  // 1. Empty state
  it('shows the empty-state placeholder when root is null', () => {
    render(<MerkleTreeView root={null} treeSize={0} />);
    const el = screen.getByText(/no entries yet/i);
    expect(el).toBeTruthy();
  });

  describe('with a 2-leaf tree', () => {
    // 2a. SVG aria-label
    it('renders an svg with the correct aria-label', () => {
      render(<MerkleTreeView root={twoLeafRoot} treeSize={2} />);
      const svg = screen.getByRole('img');
      expect(svg.getAttribute('aria-label')).toBe('Merkle tree with 2 leaves');
    });

    // 2b. Two focusable leaf buttons exist
    it('renders exactly two focusable leaf buttons', () => {
      render(<MerkleTreeView root={twoLeafRoot} treeSize={2} />);
      const buttons = screen.getAllByRole('button');
      expect(buttons.length).toBe(2);
      expect(buttons[0].getAttribute('aria-label')).toBe('select leaf 0');
      expect(buttons[1].getAttribute('aria-label')).toBe('select leaf 1');
    });

    // 2c. Click calls onSelectLeaf with the right index
    it('calls onSelectLeaf with the correct index when a leaf is clicked', () => {
      const onSelectLeaf = vi.fn();
      render(
        <MerkleTreeView
          root={twoLeafRoot}
          treeSize={2}
          onSelectLeaf={onSelectLeaf}
        />,
      );
      const [leaf0Button] = screen.getAllByRole('button');
      fireEvent.click(leaf0Button);
      expect(onSelectLeaf).toHaveBeenCalledWith(0);
    });

    // 2d. Enter keydown calls onSelectLeaf
    it('calls onSelectLeaf when Enter is pressed on a leaf', () => {
      const onSelectLeaf = vi.fn();
      render(
        <MerkleTreeView
          root={twoLeafRoot}
          treeSize={2}
          onSelectLeaf={onSelectLeaf}
        />,
      );
      const [leaf0Button] = screen.getAllByRole('button');
      fireEvent.keyDown(leaf0Button, { key: 'Enter' });
      expect(onSelectLeaf).toHaveBeenCalledWith(0);
    });

    // 2e. Space keydown calls onSelectLeaf
    it('calls onSelectLeaf when Space is pressed on a leaf', () => {
      const onSelectLeaf = vi.fn();
      render(
        <MerkleTreeView
          root={twoLeafRoot}
          treeSize={2}
          onSelectLeaf={onSelectLeaf}
        />,
      );
      const buttons = screen.getAllByRole('button');
      fireEvent.keyDown(buttons[1], { key: ' ' });
      expect(onSelectLeaf).toHaveBeenCalledWith(1);
    });

    // 2f. aria-pressed reflects selection state
    it('marks the selected leaf with aria-pressed=true, unselected with false', () => {
      render(
        <MerkleTreeView
          root={twoLeafRoot}
          treeSize={2}
          selectedLeaf={1}
        />,
      );
      const buttons = screen.getAllByRole('button');
      expect(buttons[0].getAttribute('aria-pressed')).toBe('false');
      expect(buttons[1].getAttribute('aria-pressed')).toBe('true');
    });

    // 3. highlightPath: nodes on path get data-on-path="true"
    it('marks highlighted path nodes with data-on-path="true"', () => {
      const highlightPath = new Set([LEAF0_HEX]);
      const { container } = render(
        <MerkleTreeView
          root={twoLeafRoot}
          treeSize={2}
          highlightPath={highlightPath}
        />,
      );
      const pathCircles = container.querySelectorAll('circle[data-on-path="true"]');
      expect(pathCircles.length).toBe(1);
    });

    // Interior nodes are NOT buttons
    it('does not make the interior root node a focusable button', () => {
      render(<MerkleTreeView root={twoLeafRoot} treeSize={2} />);
      const buttons = screen.getAllByRole('button');
      expect(buttons.length).toBe(2);
    });
  });
});
