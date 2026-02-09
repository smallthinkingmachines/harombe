"""
Cluster Routing Example
========================

This example demonstrates harombe's distributed inference capabilities:
- Multi-node cluster configuration
- Automatic task complexity classification
- Smart routing to appropriate hardware tiers
- Health monitoring and failover
- Load balancing across nodes

This showcases Phase 1's unique value: distributed AI orchestration across
heterogeneous hardware without cloud dependencies.

Prerequisites:
- Multiple machines with Ollama installed (or simulated with different models)
- Models pulled on each node
- harombe installed on all nodes: pip install harombe
- Network connectivity between nodes

Setup:
1. On each node: harombe start
2. On coordinator: configure cluster in ~/.harombe/harombe.yaml
3. Run this example

Usage:
    python examples/06_cluster_routing.py
"""

import asyncio

from harombe.config.loader import load_config
from harombe.coordination.cluster import ClusterManager
from harombe.coordination.router import ComplexityClassifier


async def demonstrate_routing_strategy():
    """Show how routing works without actual cluster."""
    print("\n" + "=" * 70)
    print("Part 1: Routing Strategy Overview")
    print("=" * 70 + "\n")

    classifier = ComplexityClassifier()

    # Example queries at different complexity levels
    queries = [
        {
            "query": "What is 2 + 2?",
            "expected": "simple",
            "expected_tier": 0,
        },
        {
            "query": "Read the README.md file and summarize it in one sentence.",
            "expected": "simple",
            "expected_tier": 0,
        },
        {
            "query": "Analyze all Python files in the src/ directory, identify potential bugs, and create a detailed report.",
            "expected": "complex",
            "expected_tier": 2,
        },
        {
            "query": "Search for recent papers on transformer architectures, summarize findings, compare approaches, and write a comprehensive literature review.",
            "expected": "complex",
            "expected_tier": 2,
        },
    ]

    print("Complexity Classification Examples:\n")

    for item in queries:
        query = item["query"]
        complexity = classifier.classify_query(query)

        print(f"Query: {query[:60]}...")
        print(f"  Classified as: {complexity.name}")
        print(f"  Would route to: Tier {complexity.value}")
        print()


async def simulate_cluster_routing():
    """Simulate cluster routing with local models."""
    print("\n" + "=" * 70)
    print("Part 2: Simulated Cluster Routing")
    print("=" * 70 + "\n")

    print("⚠️  Note: This example simulates cluster behavior locally.")
    print("   For real multi-node routing, configure cluster nodes in harombe.yaml\n")

    # Simulate with different local models (if available)
    queries = [
        {
            "type": "simple",
            "query": "What is the capital of France?",
            "target": "Fast local model (Tier 0)",
        },
        {
            "type": "complex",
            "query": "Explain the architectural differences between transformers and RNNs, including trade-offs.",
            "target": "Powerful model (Tier 2)",
        },
    ]

    for item in queries:
        print(f"\n{'─' * 70}")
        print(f"Query Type: {item['type'].upper()}")
        print(f"Target: {item['target']}")
        print(f"{'─' * 70}\n")
        print(f"Query: {item['query']}\n")
        print("In a real cluster, this would be routed to the appropriate node.")
        print(f"Expected behavior: Use {item['target']}\n")


async def demonstrate_cluster_config():
    """Show example cluster configuration."""
    print("\n" + "=" * 70)
    print("Part 3: Cluster Configuration")
    print("=" * 70 + "\n")

    cluster_config = """
# Example cluster configuration for ~/.harombe/harombe.yaml

cluster:
  coordinator:
    host: localhost

  routing:
    prefer_local: true        # Prefer lowest latency nodes
    fallback_strategy: graceful # Try other tiers if preferred unavailable
    load_balance: true        # Distribute across same-tier nodes

  nodes:
    # Tier 0: Fast/Local - For simple queries
    - name: laptop
      host: localhost
      port: 8000
      model: qwen2.5:3b
      tier: 0
      tags: [local, fast]

    # Tier 1: Balanced - For medium workloads
    - name: workstation
      host: 192.168.1.100
      port: 8000
      model: qwen2.5:14b
      tier: 1
      tags: [balanced]

    # Tier 2: Powerful - For complex tasks
    - name: server
      host: 192.168.1.200
      port: 8000
      model: qwen2.5:72b
      tier: 2
      tags: [powerful, gpu]

# How routing works:
# 1. Query comes in
# 2. Complexity classifier analyzes it
# 3. Simple queries → Tier 0 (fast response, low latency)
# 4. Complex queries → Tier 2 (powerful model, better quality)
# 5. Health monitoring ensures nodes are available
# 6. Load balancing distributes across same-tier nodes
"""

    print(cluster_config)


async def demonstrate_health_monitoring():
    """Show health monitoring concepts."""
    print("\n" + "=" * 70)
    print("Part 4: Health Monitoring & Failover")
    print("=" * 70 + "\n")

    concepts = [
        {
            "feature": "Health Checks",
            "description": "Periodic pings to all nodes to verify availability",
            "behavior": "Unhealthy nodes are marked unavailable",
        },
        {
            "feature": "Circuit Breaker",
            "description": "After N failures, node is temporarily disabled",
            "behavior": "Prevents cascading failures and wasted requests",
        },
        {
            "feature": "Graceful Fallback",
            "description": "If preferred tier unavailable, try other tiers",
            "behavior": "Tier 0 → Tier 1 → Tier 2 (or reverse)",
        },
        {
            "feature": "Load Balancing",
            "description": "Distribute requests across healthy same-tier nodes",
            "behavior": "Round-robin or least-loaded selection",
        },
    ]

    for concept in concepts:
        print(f"**{concept['feature']}**")
        print(f"  What: {concept['description']}")
        print(f"  How: {concept['behavior']}")
        print()


async def demonstrate_real_cluster():
    """Demonstrate real cluster usage if configured."""
    print("\n" + "=" * 70)
    print("Part 5: Real Cluster Usage")
    print("=" * 70 + "\n")

    try:
        config = load_config()

        if not config.cluster or not config.cluster.nodes:
            print("⚠️  No cluster configured.")
            print("\n   To use cluster routing:")
            print("   1. Edit ~/.harombe/harombe.yaml")
            print("   2. Add cluster section with nodes")
            print("   3. Start harombe server on each node")
            print("   4. Run: harombe cluster status")
            print("   5. Run this example again\n")
            return

        print(f"✓ Cluster configured with {len(config.cluster.nodes)} nodes:\n")

        for node in config.cluster.nodes:
            print(f"  - {node.name}")
            print(f"    Host: {node.host}:{node.port}")
            print(f"    Model: {node.model}")
            print(f"    Tier: {node.tier}")
            print()

        print("Creating cluster manager...\n")
        manager = ClusterManager(config.cluster)

        # Initialize cluster
        print("Initializing cluster...")
        await manager.initialize()

        print("\nCluster Status:")
        status = manager.get_cluster_status()

        print(f"  Total nodes: {status['total_nodes']}")
        print(f"  Healthy nodes: {status['healthy_nodes']}")
        print(f"  Unhealthy nodes: {status['unhealthy_nodes']}")

        if status["healthy_nodes"] == 0:
            print("\n⚠️  No healthy nodes available.")
            print("   Make sure harombe is running on configured nodes:")
            print("   - harombe start (on each node)")
            return

        # Try routing a query
        print("\n\nTesting query routing...\n")

        queries = [
            "What is 2 + 2?",  # Simple
            "Explain quantum computing in detail with examples.",  # Complex
        ]

        for query in queries:
            print(f"Query: {query}")
            classifier = ComplexityClassifier()
            complexity = classifier.classify_query(query)
            print(f"  Complexity: {complexity.name}")

            # Get appropriate node
            tier = complexity.value
            node = manager.select_node(tier)

            if node:
                print(f"  Selected node: {node.name} (tier {node.tier})")
                print(f"  Model: {node.model}")
                print(f"  Endpoint: {node.host}:{node.port}")
            else:
                print(f"  ⚠️  No healthy node available for tier {tier}")

            print()

    except Exception as e:
        print(f"✗ Error: {e}\n")
        print("Make sure:")
        print("  1. Cluster is configured in ~/.harombe/harombe.yaml")
        print("  2. Nodes are running (harombe start on each)")
        print("  3. Network connectivity is working")


async def main():
    """Run all cluster routing examples."""
    print("\n" + "=" * 70)
    print("Harombe Cluster Routing Examples")
    print("=" * 70)
    print("\nThese examples demonstrate distributed inference capabilities:")
    print("- Multi-node orchestration")
    print("- Automatic complexity classification")
    print("- Smart routing to appropriate hardware")
    print("- Health monitoring and failover")
    print("- Load balancing\n")

    # Part 1: Show routing strategy
    await demonstrate_routing_strategy()

    # Part 2: Simulate local routing
    await simulate_cluster_routing()

    # Part 3: Show configuration
    await demonstrate_cluster_config()

    # Part 4: Explain health monitoring
    await demonstrate_health_monitoring()

    # Part 5: Try real cluster if available
    await demonstrate_real_cluster()

    print("\n" + "=" * 70)
    print("Examples Complete!")
    print("=" * 70)
    print("\nNext Steps:")
    print("  1. Configure cluster nodes in ~/.harombe/harombe.yaml")
    print("  2. Start servers: harombe start (on each node)")
    print("  3. Check status: harombe cluster status")
    print("  4. Use cluster in your code with ClusterManager")
    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        raise
