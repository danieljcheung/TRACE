/**
 * D3.js Force-Directed Graph for TRACE
 */
const Graph = {
    // State
    svg: null,
    simulation: null,
    container: null,
    tooltip: null,

    nodes: [],
    links: [],

    // D3 selections
    nodeGroup: null,
    linkGroup: null,
    labelGroup: null,

    // Config
    config: {
        width: 800,
        height: 500,
        nodeRadius: {
            email: 25,
            username: 15,
            account: 12,
            personal_info: 12,
            breach: 14,
            domain: 12,
        },
        forces: {
            charge: -300,
            linkDistance: 100,
            centerStrength: 0.05,
            collisionRadius: 30,
        },
    },

    /**
     * Initialize the graph
     * @param {string} containerId - Container element ID
     */
    init(containerId) {
        this.container = document.getElementById(containerId);
        if (!this.container) {
            console.error(`Graph container #${containerId} not found`);
            return;
        }

        // Clear existing
        this.container.innerHTML = '';
        this.nodes = [];
        this.links = [];

        // Get dimensions
        const rect = this.container.getBoundingClientRect();
        this.config.width = rect.width || 800;
        this.config.height = rect.height || 500;

        // Create SVG
        this.svg = d3.select(this.container)
            .append('svg')
            .attr('class', 'graph-svg')
            .attr('width', '100%')
            .attr('height', '100%')
            .attr('viewBox', `0 0 ${this.config.width} ${this.config.height}`);

        // Add zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.2, 4])
            .on('zoom', (event) => {
                this.graphGroup.attr('transform', event.transform);
            });

        this.svg.call(zoom);

        // Create main group for zoom/pan
        this.graphGroup = this.svg.append('g')
            .attr('class', 'graph-group');

        // Create groups for links and nodes (links first so nodes render on top)
        this.linkGroup = this.graphGroup.append('g').attr('class', 'links');
        this.labelGroup = this.graphGroup.append('g').attr('class', 'link-labels');
        this.nodeGroup = this.graphGroup.append('g').attr('class', 'nodes');

        // Create tooltip
        this.createTooltip();

        // Create controls
        this.createControls();

        // Create legend
        this.createLegend();

        // Initialize simulation
        this.simulation = d3.forceSimulation()
            .force('link', d3.forceLink().id(d => d.id).distance(this.config.forces.linkDistance))
            .force('charge', d3.forceManyBody().strength(this.config.forces.charge))
            .force('center', d3.forceCenter(this.config.width / 2, this.config.height / 2).strength(this.config.forces.centerStrength))
            .force('collision', d3.forceCollide().radius(this.config.forces.collisionRadius))
            .on('tick', () => this.tick());

        // Set initial nodes/links (empty)
        this.simulation.nodes(this.nodes);
        this.simulation.force('link').links(this.links);
    },

    /**
     * Create tooltip element
     */
    createTooltip() {
        this.tooltip = document.createElement('div');
        this.tooltip.className = 'graph-tooltip';
        this.tooltip.innerHTML = `
            <div class="graph-tooltip__title"></div>
            <div class="graph-tooltip__type"></div>
            <div class="graph-tooltip__desc"></div>
            <div class="graph-tooltip__source"></div>
        `;
        this.container.appendChild(this.tooltip);
    },

    /**
     * Create control buttons
     */
    createControls() {
        const controls = document.createElement('div');
        controls.className = 'graph-controls';
        controls.innerHTML = `
            <button class="graph-control-btn" id="graph-zoom-in" title="Zoom In">+</button>
            <button class="graph-control-btn" id="graph-zoom-out" title="Zoom Out">−</button>
            <button class="graph-control-btn" id="graph-reset" title="Reset View">⟲</button>
            <button class="graph-control-btn" id="graph-fullscreen" title="Fullscreen">⛶</button>
        `;
        this.container.appendChild(controls);

        // Zoom in
        document.getElementById('graph-zoom-in').addEventListener('click', () => {
            this.svg.transition().call(
                d3.zoom().scaleBy,
                1.5
            );
        });

        // Zoom out
        document.getElementById('graph-zoom-out').addEventListener('click', () => {
            this.svg.transition().call(
                d3.zoom().scaleBy,
                0.67
            );
        });

        // Reset
        document.getElementById('graph-reset').addEventListener('click', () => {
            this.svg.transition().call(
                d3.zoom().transform,
                d3.zoomIdentity
            );
        });

        // Fullscreen
        document.getElementById('graph-fullscreen').addEventListener('click', () => {
            this.container.classList.toggle('graph-container--fullscreen');
            // Resize after toggle
            setTimeout(() => this.resize(), 100);
        });
    },

    /**
     * Create legend
     */
    createLegend() {
        const legend = document.createElement('div');
        legend.className = 'graph-legend';
        legend.innerHTML = `
            <div class="graph-legend__title">Node Types</div>
            <div class="graph-legend__item">
                <div class="graph-legend__shape graph-legend__shape--email"></div>
                <span class="graph-legend__label">Email (seed)</span>
            </div>
            <div class="graph-legend__item">
                <div class="graph-legend__shape graph-legend__shape--account"></div>
                <span class="graph-legend__label">Account</span>
            </div>
            <div class="graph-legend__item">
                <div class="graph-legend__shape graph-legend__shape--personal"></div>
                <span class="graph-legend__label">Personal Info</span>
            </div>
            <div class="graph-legend__item">
                <div class="graph-legend__shape graph-legend__shape--breach"></div>
                <span class="graph-legend__label">Breach</span>
            </div>
        `;
        this.container.appendChild(legend);
    },

    /**
     * Add a node to the graph
     * @param {object} finding - Finding object from backend
     */
    addNode(finding) {
        // Check if node already exists
        if (this.nodes.find(n => n.id === finding.id)) {
            return;
        }

        // Create node data
        const node = {
            id: finding.id,
            type: finding.type,
            severity: finding.severity,
            title: finding.title,
            description: finding.description,
            source: finding.source,
            sourceUrl: finding.source_url,
            data: finding.data || {},
            isNew: true,
        };

        // Set initial position near parent or center
        if (finding.parent_id) {
            const parent = this.nodes.find(n => n.id === finding.parent_id);
            if (parent) {
                node.x = parent.x + (Math.random() - 0.5) * 100;
                node.y = parent.y + (Math.random() - 0.5) * 100;
            }
        }

        if (!node.x) {
            node.x = this.config.width / 2 + (Math.random() - 0.5) * 50;
            node.y = this.config.height / 2 + (Math.random() - 0.5) * 50;
        }

        this.nodes.push(node);

        // Add link to parent
        if (finding.parent_id) {
            this.links.push({
                source: finding.parent_id,
                target: finding.id,
                label: finding.link_label || '',
            });
        }

        // Update visualization
        this.update();

        // Play sound
        Audio.beep();

        // Remove "new" flag after animation
        setTimeout(() => {
            node.isNew = false;
        }, 500);
    },

    /**
     * Update the visualization
     */
    update() {
        // Update links
        const link = this.linkGroup
            .selectAll('.link')
            .data(this.links, d => `${d.source.id || d.source}-${d.target.id || d.target}`);

        link.exit().remove();

        link.enter()
            .append('line')
            .attr('class', 'link')
            .merge(link);

        // Update link labels
        const linkLabel = this.labelGroup
            .selectAll('.link-label')
            .data(this.links.filter(d => d.label), d => `${d.source.id || d.source}-${d.target.id || d.target}`);

        linkLabel.exit().remove();

        linkLabel.enter()
            .append('text')
            .attr('class', 'link-label')
            .merge(linkLabel)
            .text(d => d.label);

        // Update nodes
        const node = this.nodeGroup
            .selectAll('.node')
            .data(this.nodes, d => d.id);

        node.exit().remove();

        const nodeEnter = node.enter()
            .append('g')
            .attr('class', d => `node node--${d.type}${d.isNew ? ' node--new' : ''}${d.type === 'email' ? ' node--center' : ''}`)
            .call(this.drag())
            .on('mouseover', (event, d) => this.showTooltip(event, d))
            .on('mouseout', () => this.hideTooltip())
            .on('click', (event, d) => this.onNodeClick(event, d));

        // Add shapes based on type
        nodeEnter.each((d, i, nodes) => {
            const g = d3.select(nodes[i]);
            const radius = this.config.nodeRadius[d.type] || 12;

            if (d.type === 'personal_info') {
                // Square for personal info
                g.append('rect')
                    .attr('width', radius * 2)
                    .attr('height', radius * 2)
                    .attr('x', -radius)
                    .attr('y', -radius)
                    .attr('rx', 3);
            } else if (d.type === 'breach') {
                // Triangle for breach
                const size = radius * 1.5;
                g.append('polygon')
                    .attr('points', `0,${-size} ${size},${size} ${-size},${size}`);
            } else {
                // Circle for others
                g.append('circle')
                    .attr('r', radius);
            }
        });

        // Add labels
        nodeEnter.append('text')
            .attr('class', 'node-label node-label--title')
            .attr('dy', d => {
                const radius = this.config.nodeRadius[d.type] || 12;
                return radius + 15;
            })
            .text(d => this.truncateLabel(d.title, 20));

        // Update simulation
        this.simulation.nodes(this.nodes);
        this.simulation.force('link').links(this.links);
        this.simulation.alpha(0.3).restart();
    },

    /**
     * Tick function for simulation
     */
    tick() {
        // Update link positions
        this.linkGroup.selectAll('.link')
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        // Update link label positions
        this.labelGroup.selectAll('.link-label')
            .attr('x', d => (d.source.x + d.target.x) / 2)
            .attr('y', d => (d.source.y + d.target.y) / 2);

        // Update node positions
        this.nodeGroup.selectAll('.node')
            .attr('transform', d => `translate(${d.x}, ${d.y})`);
    },

    /**
     * Create drag behavior
     */
    drag() {
        return d3.drag()
            .on('start', (event, d) => {
                if (!event.active) this.simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            })
            .on('drag', (event, d) => {
                d.fx = event.x;
                d.fy = event.y;
            })
            .on('end', (event, d) => {
                if (!event.active) this.simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            });
    },

    /**
     * Show tooltip
     */
    showTooltip(event, d) {
        const severityClass = `graph-tooltip__severity--${d.severity}`;

        this.tooltip.querySelector('.graph-tooltip__title').innerHTML =
            `${d.title} <span class="graph-tooltip__severity ${severityClass}">${d.severity}</span>`;
        this.tooltip.querySelector('.graph-tooltip__type').textContent = d.type.replace('_', ' ');
        this.tooltip.querySelector('.graph-tooltip__desc').textContent = d.description;
        this.tooltip.querySelector('.graph-tooltip__source').textContent =
            d.sourceUrl ? `Source: ${d.source}` : `Source: ${d.source}`;

        // Position tooltip
        const rect = this.container.getBoundingClientRect();
        let x = event.clientX - rect.left + 15;
        let y = event.clientY - rect.top + 15;

        // Keep within bounds
        const tooltipRect = this.tooltip.getBoundingClientRect();
        if (x + tooltipRect.width > rect.width) {
            x = event.clientX - rect.left - tooltipRect.width - 15;
        }
        if (y + tooltipRect.height > rect.height) {
            y = event.clientY - rect.top - tooltipRect.height - 15;
        }

        this.tooltip.style.left = `${x}px`;
        this.tooltip.style.top = `${y}px`;
        this.tooltip.classList.add('graph-tooltip--visible');
    },

    /**
     * Hide tooltip
     */
    hideTooltip() {
        this.tooltip.classList.remove('graph-tooltip--visible');
    },

    /**
     * Handle node click
     */
    onNodeClick(event, d) {
        // Open source URL if available
        if (d.sourceUrl) {
            window.open(d.sourceUrl, '_blank');
        }
    },

    /**
     * Truncate label text
     */
    truncateLabel(text, maxLength) {
        if (!text) return '';
        // Remove common prefixes
        text = text.replace(/^(Username|Name|Location|Email|Domain|Employer): ?/i, '');
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength - 3) + '...';
    },

    /**
     * Resize graph
     */
    resize() {
        const rect = this.container.getBoundingClientRect();
        this.config.width = rect.width;
        this.config.height = rect.height;

        this.svg.attr('viewBox', `0 0 ${this.config.width} ${this.config.height}`);
        this.simulation.force('center', d3.forceCenter(this.config.width / 2, this.config.height / 2));
        this.simulation.alpha(0.3).restart();
    },

    /**
     * Get node count
     */
    getNodeCount() {
        return this.nodes.length;
    },

    /**
     * Get nodes by severity
     */
    getNodesBySeverity() {
        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        this.nodes.forEach(n => {
            if (counts[n.severity] !== undefined) {
                counts[n.severity]++;
            }
        });
        return counts;
    },

    /**
     * Clear the graph
     */
    clear() {
        this.nodes = [];
        this.links = [];
        this.update();
    }
};
