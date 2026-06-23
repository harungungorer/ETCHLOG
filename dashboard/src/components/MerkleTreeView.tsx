import { useState } from 'react';
import type { TreeNode } from '../verifier/merkle';

export interface MerkleTreeViewProps {
  root: TreeNode | null;
  treeSize: number;
  highlightPath?: Set<string>;
  selectedLeaf?: number | null;
  onSelectLeaf?: (leafIndex: number) => void;
}

// Layout constants
const NODE_RADIUS = 14;
const H_SPACING = 52;  // horizontal spacing between leaf nodes
const V_SPACING = 64;  // vertical spacing between depth levels
const PADDING = 32;    // outer padding

interface PositionedNode {
  node: TreeNode;
  x: number;
  y: number;
  depth: number;
}

interface Edge {
  x1: number;
  y1: number;
  x2: number;
  y2: number;
}

interface LayoutResult {
  nodes: PositionedNode[];
  edges: Edge[];
  svgWidth: number;
  svgHeight: number;
}

/**
 * Compute tree depth (max distance from root to any leaf).
 */
function treeDepth(node: TreeNode): number {
  if (node.isLeaf) return 0;
  const leftDepth = node.left ? treeDepth(node.left) : 0;
  const rightDepth = node.right ? treeDepth(node.right) : 0;
  return 1 + Math.max(leftDepth, rightDepth);
}

/**
 * Assign x positions to all leaf nodes left-to-right, then derive interior node
 * x as the midpoint of its children. y is determined by depth.
 *
 * Returns a flat list of positioned nodes and their connecting edges.
 */
function computeLayout(root: TreeNode): LayoutResult {
  const maxDepth = treeDepth(root);
  const nodes: PositionedNode[] = [];
  const edges: Edge[] = [];

  // Collect all leaf nodes in left-to-right order (in-order traversal)
  const leafNodes: TreeNode[] = [];
  function collectLeaves(node: TreeNode): void {
    if (node.isLeaf) {
      leafNodes.push(node);
    } else {
      if (node.left) collectLeaves(node.left);
      if (node.right) collectLeaves(node.right);
    }
  }
  collectLeaves(root);

  // Assign x positions to leaves
  const leafX = new Map<string, number>();
  leafNodes.forEach((leaf, i) => {
    leafX.set(leaf.hashHex, PADDING + i * H_SPACING);
  });

  // Recursively position all nodes, returning this node's x
  function positionNode(node: TreeNode, depth: number): number {
    const y = PADDING + depth * V_SPACING;

    let x: number;
    if (node.isLeaf) {
      x = leafX.get(node.hashHex)!;
    } else {
      const leftX = node.left ? positionNode(node.left, depth + 1) : 0;
      const rightX = node.right ? positionNode(node.right, depth + 1) : 0;

      if (node.left && node.right) {
        x = (leftX + rightX) / 2;
      } else if (node.left) {
        x = leftX;
      } else if (node.right) {
        x = rightX;
      } else {
        x = PADDING;
      }

      // Add edges to children
      if (node.left) {
        const childY = PADDING + (depth + 1) * V_SPACING;
        const childX = node.left.isLeaf
          ? leafX.get(node.left.hashHex)!
          : ((): number => {
              // x will have been computed already by positionNode above; retrieve from nodes array
              const found = nodes.find((n) => n.node.hashHex === node.left!.hashHex);
              return found ? found.x : x;
            })();
        edges.push({ x1: x, y1: y, x2: childX, y2: childY });
      }
      if (node.right) {
        const childY = PADDING + (depth + 1) * V_SPACING;
        const childX = node.right.isLeaf
          ? leafX.get(node.right.hashHex)!
          : ((): number => {
              const found = nodes.find((n) => n.node.hashHex === node.right!.hashHex);
              return found ? found.x : x;
            })();
        edges.push({ x1: x, y1: y, x2: childX, y2: childY });
      }
    }

    nodes.push({ node, x, y, depth });
    return x;
  }

  positionNode(root, 0);

  const maxX = Math.max(...nodes.map((n) => n.x)) + PADDING + NODE_RADIUS;
  const maxY = PADDING + maxDepth * V_SPACING + PADDING + NODE_RADIUS;
  const svgWidth = Math.max(maxX, 120);
  const svgHeight = Math.max(maxY, 80);

  return { nodes, edges, svgWidth, svgHeight };
}

function nodeLabel(node: TreeNode): string {
  const hexSnippet = node.hashHex.slice(0, 12);
  if (node.isLeaf) {
    return `leaf #${node.leafIndex}: ${hexSnippet}…`;
  }
  return `node [${node.lo},${node.hi}): ${hexSnippet}…`;
}

export function MerkleTreeView({
  root,
  treeSize,
  highlightPath,
  selectedLeaf,
  onSelectLeaf,
}: MerkleTreeViewProps): JSX.Element {
  // Tracks the keyboard-focused leaf so we can draw a visible focus ring (SVG outline rendering is
  // inconsistent across browsers). Declared before any early return to satisfy the rules of hooks.
  const [focusedLeaf, setFocusedLeaf] = useState<number | null>(null);

  if (root === null) {
    return (
      <div className="flex items-center justify-center rounded border border-gray-800 bg-gray-900 p-8">
        <p className="font-mono text-sm text-gray-500">
          No entries yet — append one to grow the tree.
        </p>
      </div>
    );
  }

  const { nodes, edges, svgWidth, svgHeight } = computeLayout(root);

  function getNodeStyle(node: TreeNode): {
    fill: string;
    stroke: string;
    strokeWidth: number;
  } {
    const isOnPath = highlightPath?.has(node.hashHex) ?? false;
    const isSelected = node.isLeaf && node.leafIndex === selectedLeaf;

    if (isSelected) {
      return { fill: '#34d399', stroke: '#6ee7b7', strokeWidth: 2.5 }; // emerald-400
    }
    if (isOnPath) {
      return { fill: '#fbbf24', stroke: '#fde68a', strokeWidth: 2.5 }; // amber-400
    }
    if (node.isLeaf) {
      return { fill: '#374151', stroke: '#6b7280', strokeWidth: 1.5 }; // gray-700/500
    }
    return { fill: '#1f2937', stroke: '#4b5563', strokeWidth: 1.5 }; // gray-800/600
  }

  function handleKeyDown(
    e: React.KeyboardEvent<SVGGElement>,
    leafIndex: number,
  ): void {
    if (e.key === 'Enter' || e.key === ' ') {
      if (e.key === ' ') e.preventDefault();
      onSelectLeaf?.(leafIndex);
    }
  }

  return (
    <div className="overflow-auto rounded border border-gray-800 bg-gray-900 p-2">
      <svg
        width={svgWidth}
        height={svgHeight}
        role="img"
        aria-label={`Merkle tree with ${treeSize} leaves`}
      >
        {/* Edges rendered first so nodes sit on top */}
        {edges.map((edge, i) => (
          <line
            key={i}
            x1={edge.x1}
            y1={edge.y1}
            x2={edge.x2}
            y2={edge.y2}
            stroke="#4b5563"
            strokeWidth={1.5}
          />
        ))}

        {/* Nodes */}
        {nodes.map(({ node, x, y }) => {
          const style = getNodeStyle(node);
          const isSelected = node.isLeaf && node.leafIndex === selectedLeaf;
          const isOnPath = highlightPath?.has(node.hashHex) ?? false;

          if (node.isLeaf) {
            const isFocused = node.leafIndex === focusedLeaf;
            return (
              <g
                key={node.hashHex}
                tabIndex={0}
                role="button"
                aria-label={`select leaf ${node.leafIndex}`}
                aria-pressed={isSelected}
                onClick={() => onSelectLeaf?.(node.leafIndex)}
                onKeyDown={(e) => handleKeyDown(e, node.leafIndex)}
                onFocus={() => setFocusedLeaf(node.leafIndex)}
                onBlur={() => setFocusedLeaf(null)}
                style={{ cursor: 'pointer', outline: 'none' }}
              >
                {/* Visible keyboard focus indicator (solid sky ring), drawn beneath the node. */}
                {isFocused && (
                  <circle
                    cx={x}
                    cy={y}
                    r={NODE_RADIUS + 5}
                    fill="none"
                    stroke="#38bdf8"
                    strokeWidth={2.5}
                    data-focus-ring="true"
                  />
                )}
                <circle
                  cx={x}
                  cy={y}
                  r={NODE_RADIUS}
                  fill={style.fill}
                  stroke={style.stroke}
                  strokeWidth={style.strokeWidth}
                  data-on-path={isOnPath ? 'true' : undefined}
                />
                {/* Selection ring (emerald dashed) — distinct from the focus ring. */}
                {isSelected && (
                  <circle
                    cx={x}
                    cy={y}
                    r={NODE_RADIUS + 4}
                    fill="none"
                    stroke="#34d399"
                    strokeWidth={1.5}
                    strokeDasharray="3 2"
                  />
                )}
                <title>{nodeLabel(node)}</title>
              </g>
            );
          }

          // Interior node — not focusable/clickable
          return (
            <g key={node.hashHex}>
              <circle
                cx={x}
                cy={y}
                r={NODE_RADIUS}
                fill={style.fill}
                stroke={style.stroke}
                strokeWidth={style.strokeWidth}
                data-on-path={isOnPath ? 'true' : undefined}
              />
              <title>{nodeLabel(node)}</title>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
