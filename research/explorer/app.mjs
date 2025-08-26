import Graph from "https://cdn.jsdelivr.net/npm/graphology@0.25.4/+esm";
import Sigma from "https://cdn.jsdelivr.net/npm/sigma@3.0.0/+esm";
import forceAtlas2 from "https://cdn.jsdelivr.net/npm/graphology-layout-forceatlas2@0.10.1/+esm";

const container = document.getElementById("container");
const qmaxEl = document.getElementById("qmax");
const qmaxVal = document.getElementById("qmax-val");
const minjointEl = document.getElementById("minjoint");
const minjointVal = document.getElementById("minjoint-val");
const maxedgesEl = document.getElementById("maxedges");
const maxedgesVal = document.getElementById("maxedges-val");
const showComp = document.getElementById("show-comp");
const showCompete = document.getElementById("show-compete");
const searchEl = document.getElementById("search");

const res = await fetch("data/graph.json");
const { nodes, edges } = await res.json();

const graph = new Graph();
// Persist node positions across rebuilds to avoid layout jumps
const POS = new Map(); // id -> {x, y}
const MOVED = new Set(); // nodes manually dragged by the user

const RAW = { nodes, edges };

function buildGraph() {
  // Snapshot current positions before we clear
  graph.forEachNode((key, attrs) => {
    if (typeof attrs.x === "number" && typeof attrs.y === "number") {
      POS.set(key, { x: attrs.x, y: attrs.y });
    }
  });
  graph.clear();
  const qmax = parseFloat(qmaxEl.value);
  const minJoint = parseInt(minjointEl.value, 10);
  const maxEdges = parseInt(maxedgesEl.value, 10);
  const rels = new Set();
  if (showComp.checked) rels.add("complementary");
  if (showCompete.checked) rels.add("competitive");

  const keepNode = new Set();
  const N = Math.max(1, RAW.nodes.length);
  let i = 0;
  RAW.nodes.forEach((n) => {
    const prev = POS.get(n.id);
    const angle = (2 * Math.PI * i) / N;
    const x = prev?.x ?? Math.cos(angle);
    const y = prev?.y ?? Math.sin(angle);
    graph.addNode(n.id, {
      label: n.label,
      size: 2 + 20 * (n.support || 0),
      color: "#888",
      support: n.support || 0,
      x,
      y,
    });
    i += 1;
  });

  let filtered = RAW.edges
    // Only keep edges that meet the significance threshold
    .filter((e) => typeof e.qvalue === "number" && e.qvalue <= qmax)
    // Only keep edges that meet the joint count threshold
    .filter((e) => typeof e.a === "number" && e.a >= minJoint)
    // Only keep selected relationship types
    .filter((e) => rels.has(e.relationship))
    .sort((a, b) => (b.evidence_score || 0) - (a.evidence_score || 0));

  // Dynamically cap edges based on available count and update slider range/label
  const totalEdges = filtered.length;
  // Ensure slider maximum reflects actual available edges (at least 1 to keep control usable)
  maxedgesEl.max = String(Math.max(1, totalEdges));
  // Clamp the selected maxEdges to available range
  const cappedMax = Math.min(maxEdges, Math.max(1, totalEdges));
  if (cappedMax !== maxEdges) {
    maxedgesEl.value = String(cappedMax);
  }
  // Apply cap
  filtered = filtered.slice(0, cappedMax);
  // Update badge to show cap vs total
  maxedgesVal.textContent = `${cappedMax} / ${totalEdges}`;

  filtered.forEach((e) => {
    if (!graph.hasNode(e.source) || !graph.hasNode(e.target)) return;
    keepNode.add(e.source);
    keepNode.add(e.target);
    graph.addEdgeWithKey(e.id, e.source, e.target, {
      size: 1 + Math.min(6, e.evidence_score || 0),
      color: e.relationship === "competitive" ? "#4c78a8" : "#e45756",
      label: `${e.relationship} (lift ${Number(e.lift || 0).toFixed(2)})`,
    });
  });

  graph.forEachNode((key) => {
    if (!keepNode.has(key)) graph.dropNode(key);
  });
  // Update POS with current positions
  graph.forEachNode((key, attrs) => POS.set(key, { x: attrs.x, y: attrs.y }));
}

buildGraph();
// Run FA2 once to refine initial positions, then persist
forceAtlas2.assign(graph, { iterations: 150 });
graph.forEachNode((key, attrs) => POS.set(key, { x: attrs.x, y: attrs.y }));

const renderer = new Sigma(graph, container, { renderLabels: true });

// Enable node dragging: drag to reposition a node and persist its position
let isDragging = false;
let draggedNode = null;

renderer.on("downNode", ({ node }) => {
  isDragging = true;
  draggedNode = node;
});

// Use MouseCaptor events for robust drag handling
const mouseCaptor = renderer.getMouseCaptor();

mouseCaptor.on("mousemove", ({ x, y }) => {
  if (!isDragging || !draggedNode) return;
  const pos = renderer.viewportToGraph({ x, y });
  if (!pos) return;
  graph.setNodeAttribute(draggedNode, "x", pos.x);
  graph.setNodeAttribute(draggedNode, "y", pos.y);
  POS.set(draggedNode, { x: pos.x, y: pos.y });
  MOVED.add(draggedNode);
});

mouseCaptor.on("mouseup", () => {
  isDragging = false;
  draggedNode = null;
});

mouseCaptor.on("drag", (e) => {
  if (isDragging) e.preventSigmaDefault = true;
});

function refresh() {
  qmaxVal.textContent = qmaxEl.value;
  minjointVal.textContent = minjointEl.value;
  maxedgesVal.textContent = maxedgesEl.value;
  buildGraph();
  renderer.refresh();
}

[qmaxEl, minjointEl, maxedgesEl, showComp, showCompete].forEach((el) =>
  el.addEventListener("input", refresh)
);

searchEl.addEventListener("input", () => {
  const q = (searchEl.value || "").toLowerCase();
  graph.forEachNode((key, attrs) => {
    const highlight = q && attrs.label.toLowerCase().includes(q);
    graph.setNodeAttribute(key, "color", highlight ? "#ffb703" : "#888");
  });
  renderer.refresh();
});

// Re-layout button: run FA2, but preserve positions of manually moved nodes
const relayoutBtn = document.getElementById("relayout");
relayoutBtn.addEventListener("click", () => {
  // Run ForceAtlas2 to refine the layout
  try {
    forceAtlas2.assign(graph, { iterations: 200 });
  } catch (e) {
    console.error("ForceAtlas2 failed:", e);
  }
  // Restore positions of user-moved nodes
  MOVED.forEach((id) => {
    const p = POS.get(id);
    if (p) {
      graph.setNodeAttribute(id, "x", p.x);
      graph.setNodeAttribute(id, "y", p.y);
    }
  });
  // Persist latest positions
  graph.forEachNode((key, attrs) => POS.set(key, { x: attrs.x, y: attrs.y }));
  renderer.refresh();
});
