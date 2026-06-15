import { memo, useEffect, useRef } from 'react'
import {
  ReactFlow, ReactFlowProvider, Background, Controls,
  useNodesState, useEdgesState, useReactFlow,
  MarkerType, BackgroundVariant, Handle, Position,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'

const TYPE_VAR = {
  host:          '--entity-host',
  user:          '--entity-user',
  ip:            '--entity-ip',
  domain:        '--entity-domain',
  email:         '--entity-email',
  service:       '--entity-service',
  network_range: '--entity-network',
  group:         '--entity-group',
  other:         '--entity-other',
}

const typeColor = (v) => `var(${TYPE_VAR[v] || '--muted'})`

function circularPositions(items) {
  if (items.length === 0) return []
  if (items.length === 1) return [{ x: 300, y: 250 }]
  const radius = Math.max(160, items.length * 32)
  return items.map((_, i) => {
    const angle = (2 * Math.PI * i / items.length) - Math.PI / 2
    return {
      x: 300 + radius * Math.cos(angle),
      y: 250 + radius * Math.sin(angle),
    }
  })
}

// Custom node — must be memo'd and defined at module scope so react-flow
// doesn't re-create the DOM node type on every parent render.
const EntityNode = memo(function EntityNode({ data }) {
  const { entity, isSelected } = data
  const color = typeColor(entity.type)
  return (
    <div
      className={[
        'entity-node-card',
        isSelected        ? 'selected'    : '',
        entity.compromised ? 'compromised' : '',
      ].filter(Boolean).join(' ')}
    >
      {/* Invisible anchors so react-flow can draw edges. Drag-to-connect is
          disabled at the ReactFlow level via nodesConnectable={false}. */}
      <Handle type="target" position={Position.Left}  isConnectable={false} className="entity-node-handle" />
      <Handle type="source" position={Position.Right} isConnectable={false} className="entity-node-handle" />
      <div className="entity-node-type-row">
        <span className="entity-node-dot" style={{ background: color }} />
        <span className="entity-node-type-label" style={{ color }}>
          {entity.type.replace('_', ' ')}
        </span>
        {entity.compromised && (
          <span className="entity-node-compromised-badge">CMPD</span>
        )}
      </div>
      <div className="entity-node-value">{entity.name || entity.value}</div>
      {entity.name && (
        <div className="entity-node-name">{entity.value}</div>
      )}
    </div>
  )
})

const nodeTypes = { entityNode: EntityNode }

// ── Inner component (must be inside ReactFlowProvider to use useReactFlow) ──

function GraphInner({ entities, relations, selectedEntityId, onSelectEntity }) {
  const { fitView } = useReactFlow()
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const prevCountRef = useRef(0)

  // Rebuild nodes when entities list changes.
  // When count changes (add/delete), recompute all positions and fit view.
  // When only data changes (compromised toggle etc), preserve dragged positions.
  useEffect(() => {
    const countChanged = entities.length !== prevCountRef.current
    prevCountRef.current = entities.length

    setNodes(prev => {
      const posById = countChanged
        ? new Map()
        : new Map(prev.map(n => [n.id, n.position]))
      const defaults = circularPositions(entities)
      return entities.map((ent, i) => ({
        id:       ent.id,
        type:     'entityNode',
        position: posById.get(ent.id) ?? defaults[i],
        data:     { entity: ent, isSelected: ent.id === selectedEntityId },
      }))
    })

    if (countChanged && entities.length > 0) {
      // Give react-flow one frame to measure the new nodes before fitting
      requestAnimationFrame(() => fitView({ padding: 0.3, duration: 250 }))
    }
  }, [entities, selectedEntityId, setNodes, fitView])

  // Rebuild edges when relations change
  useEffect(() => {
    setEdges(
      relations.map(rel => ({
        id:     rel.id,
        source: rel.from_entity_id,
        target: rel.to_entity_id,
        label:  rel.relationship_type,
        labelStyle: {
          fontFamily: 'monospace',
          fontSize:   9,
          fill:       'var(--muted)',
        },
        labelBgStyle: {
          fill:        'var(--surface)',
          fillOpacity: 0.88,
        },
        labelBgBorderRadius: 2,
        markerEnd: {
          type:   MarkerType.ArrowClosed,
          width:  12,
          height: 12,
          color:  '#7a8595',   // --muted in mission-control; visible on all themes
        },
        // Inline style is overridden by our CSS .react-flow__edge-path rule,
        // but keep a fallback in case CSS specificity changes.
        style: { stroke: '#7a8595', strokeWidth: 1.5 },
      }))
    )
  }, [relations, setEdges])

  const onNodeClick = (_evt, node) => onSelectEntity(node.data.entity)
  const onPaneClick = ()           => onSelectEntity(null)

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={onNodeClick}
      onPaneClick={onPaneClick}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.3 }}
      minZoom={0.15}
      maxZoom={3}
      nodesDraggable
      nodesConnectable={false}
      elementsSelectable={false}
    >
      <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="var(--border)" />
      <Controls showInteractive={false} />
    </ReactFlow>
  )
}

// ── Public component ─────────────────────────────────────────────────────────

export default function EntityGraph({ entities, relations, selectedEntityId, onSelectEntity }) {
  if (entities.length === 0) {
    return (
      <div className="entity-graph-wrap" style={{
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}>
        <div style={{ textAlign: 'center', color: 'var(--dim)' }}>
          <div style={{ fontSize: 32, marginBottom: 8 }}>◇</div>
          <div style={{ fontSize: 13, color: 'var(--muted)' }}>No entities yet.</div>
          <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 4 }}>
            Add entities using the button above to see the graph.
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="entity-graph-wrap">
      <ReactFlowProvider>
        <GraphInner
          entities={entities}
          relations={relations}
          selectedEntityId={selectedEntityId}
          onSelectEntity={onSelectEntity}
        />
      </ReactFlowProvider>
    </div>
  )
}
