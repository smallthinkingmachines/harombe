"""Smart routing and task complexity classification."""

import re
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar

from harombe.llm.client import Message


class TaskComplexity(Enum):
    """Task complexity levels."""

    SIMPLE = 0  # Quick queries, factual questions
    MEDIUM = 1  # Multi-step reasoning, moderate context
    COMPLEX = 2  # Deep analysis, large context, code generation


@dataclass
class RoutingDecision:
    """Result of routing analysis."""

    complexity: TaskComplexity
    recommended_tier: int
    reasoning: str
    estimated_tokens: int


class ComplexityClassifier:
    """
    Classifies task complexity based on query characteristics.

    Uses heuristics to estimate computational requirements without
    needing to call an LLM.
    """

    # Keywords indicating complex tasks
    COMPLEX_KEYWORDS: ClassVar[set[str]] = {
        "analyze",
        "compare",
        "explain",
        "debug",
        "refactor",
        "implement",
        "design",
        "optimize",
        "review",
        "comprehensive",
        "detailed",
        "thoroughly",
    }

    # Keywords indicating simple tasks
    SIMPLE_KEYWORDS: ClassVar[set[str]] = {
        "what",
        "when",
        "where",
        "who",
        "define",
        "list",
        "show",
        "tell",
        "quick",
        "simple",
        "brief",
    }

    def __init__(self) -> None:
        """Initialize classifier."""
        pass

    def classify_query(
        self,
        query: str,
        context: list[Message] | None = None,
    ) -> TaskComplexity:
        """
        Classify query complexity.

        Args:
            query: User query text
            context: Optional conversation history

        Returns:
            TaskComplexity level
        """
        # Calculate various complexity signals
        signals = {
            "length": self._score_length(query),
            "keywords": self._score_keywords(query),
            "context_size": self._score_context(context),
            "code_presence": self._score_code_presence(query),
            "question_complexity": self._score_question_complexity(query),
        }

        # Weighted scoring with emphasis on code and keywords
        total_score = (
            signals["length"] * 0.10
            + signals["keywords"] * 0.40
            + signals["context_size"] * 0.15
            + signals["code_presence"] * 0.30
            + signals["question_complexity"] * 0.05
        )

        # Classify based on total score with lower thresholds
        if total_score >= 0.55:
            return TaskComplexity.COMPLEX
        elif total_score >= 0.25:
            return TaskComplexity.MEDIUM
        else:
            return TaskComplexity.SIMPLE

    def _score_length(self, query: str) -> float:
        """Score based on query length."""
        words = len(query.split())
        if words > 80:
            return 1.0
        elif words > 30:
            return 0.7
        elif words > 15:
            return 0.4
        else:
            return 0.0

    def _score_keywords(self, query: str) -> float:
        """Score based on keyword presence."""
        query_lower = query.lower()
        set(query_lower.split())

        # Check for complex keywords
        complex_matches = sum(1 for kw in self.COMPLEX_KEYWORDS if kw in query_lower)
        simple_matches = sum(1 for kw in self.SIMPLE_KEYWORDS if kw in query_lower)

        if complex_matches > 0:
            return min(1.0, 0.6 + complex_matches * 0.15)
        elif simple_matches > 0:
            return max(0.0, 0.1 - simple_matches * 0.05)
        else:
            return 0.3  # Neutral

    def _score_context(self, context: list[Message] | None) -> float:
        """Score based on conversation context size."""
        if not context:
            return 0.0

        total_tokens = sum(len(msg.content.split()) for msg in context)
        if total_tokens > 1500:
            return 1.0
        elif total_tokens > 800:
            return 0.7
        elif total_tokens > 300:
            return 0.4
        else:
            return 0.1

    def _score_code_presence(self, query: str) -> float:
        """Score based on code-related indicators."""
        # Check for code blocks
        if "```" in query:
            return 1.0

        # Check for code-like patterns
        code_indicators = [
            r"def\s+\w+",  # Python function
            r"class\s+\w+",  # Class definition
            r"import\s+\w+",  # Import statement
            r"function\s+\w+",  # JS function
            r"\{[\s\S]*\}",  # Object/dict literal
            r"for\s+\w+\s+in",  # Loop
            r"if\s+.*:",  # Conditional
        ]

        for pattern in code_indicators:
            if re.search(pattern, query):
                return 0.8

        return 0.0

    def _score_question_complexity(self, query: str) -> float:
        """Score based on question complexity."""
        # Multiple questions suggest complexity
        question_marks = query.count("?")
        if question_marks > 2:
            return 0.8
        elif question_marks > 1:
            return 0.5

        # Check for compound sentences
        conjunctions = ["and", "but", "however", "moreover", "furthermore"]
        conjunction_count = sum(1 for conj in conjunctions if conj in query.lower())
        if conjunction_count > 2:
            return 0.6

        return 0.0


class Router:
    """
    Smart router for selecting appropriate nodes based on task characteristics.

    Combines complexity classification with node capabilities and health.
    """

    def __init__(self, classifier: ComplexityClassifier | None = None):
        """
        Initialize router.

        Args:
            classifier: Optional complexity classifier (creates default if None)
        """
        self.classifier = classifier or ComplexityClassifier()

    def analyze_routing(
        self,
        query: str,
        context: list[Message] | None = None,
    ) -> RoutingDecision:
        """
        Analyze query and determine routing.

        Args:
            query: User query text
            context: Optional conversation history

        Returns:
            RoutingDecision with recommended tier and reasoning
        """
        # Classify complexity
        complexity = self.classifier.classify_query(query, context)

        # Estimate token count
        estimated_tokens = self._estimate_tokens(query, context)

        # Map complexity to tier
        if complexity == TaskComplexity.COMPLEX:
            tier = 2
            reasoning = "Complex task requiring powerful model"
        elif complexity == TaskComplexity.MEDIUM:
            tier = 1
            reasoning = "Medium complexity task for balanced model"
        else:
            tier = 0
            reasoning = "Simple task suitable for fast model"

        # Adjust based on token count
        if estimated_tokens > 4000 and tier < 2:
            tier = 2
            reasoning += " (large context requires tier 2)"
        elif estimated_tokens > 2000 and tier < 1:
            tier = 1
            reasoning += " (moderate context requires tier 1)"

        return RoutingDecision(
            complexity=complexity,
            recommended_tier=tier,
            reasoning=reasoning,
            estimated_tokens=estimated_tokens,
        )

    def _estimate_tokens(
        self,
        query: str,
        context: list[Message] | None = None,
    ) -> int:
        """
        Estimate total token count.

        Uses rough approximation: 1 token ≈ 4 characters.
        """
        total_chars = len(query)
        if context:
            total_chars += sum(len(msg.content) for msg in context)

        return total_chars // 4
