"""
=============================================================================
Elasticsearch Sink
=============================================================================
Manages Elasticsearch connection, index creation, and document indexing
for the deception-SOC logger service.
=============================================================================
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from elasticsearch import AsyncElasticsearch

logger = logging.getLogger("logger.elasticsearch")

ELASTICSEARCH_HOST = os.getenv("ELASTICSEARCH_HOST", "http://elasticsearch:9200")

# ---------------------------------------------------------------------------
# Index Definitions
# ---------------------------------------------------------------------------
INDEX_MAPPINGS = {
    "deception-sessions": {
        "mappings": {
            "properties": {
                "attacker_ip": {"type": "ip"},
                "username": {"type": "keyword"},
                "session_start": {"type": "date"},
                "session_end": {"type": "date"},
                "duration_seconds": {"type": "float"},
                "commands": {
                    "type": "nested",
                    "properties": {
                        "command": {"type": "text"},
                        "cwd": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                    },
                },
                "credentials_tried": {
                    "type": "nested",
                    "properties": {
                        "username": {"type": "keyword"},
                        "password": {"type": "keyword"},
                        "success": {"type": "boolean"},
                        "timestamp": {"type": "date"},
                    },
                },
                "files_accessed": {
                    "type": "nested",
                    "properties": {
                        "path": {"type": "keyword"},
                        "found": {"type": "boolean"},
                        "timestamp": {"type": "date"},
                    },
                },
                "download_attempts": {
                    "type": "nested",
                    "properties": {
                        "url": {"type": "text"},
                        "timestamp": {"type": "date"},
                    },
                },
                "service": {"type": "keyword"},
                "honeypot_type": {"type": "keyword"},
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
        },
    },
    "deception-commands": {
        "mappings": {
            "properties": {
                "attacker_ip": {"type": "ip"},
                "command": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "cwd": {"type": "keyword"},
                "timestamp": {"type": "date"},
                "session_id": {"type": "keyword"},
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
        },
    },
    "deception-credentials": {
        "mappings": {
            "properties": {
                "attacker_ip": {"type": "ip"},
                "username": {"type": "keyword"},
                "password": {"type": "keyword"},
                "success": {"type": "boolean"},
                "timestamp": {"type": "date"},
                "session_id": {"type": "keyword"},
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
        },
    },
    "deception-http": {
        "mappings": {
            "properties": {
                "attacker_ip": {"type": "ip"},
                "requests": {
                    "type": "nested",
                    "properties": {
                        "method": {"type": "keyword"},
                        "path": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                        "user_agent": {"type": "text"},
                    },
                },
                "login_attempts": {
                    "type": "nested",
                    "properties": {
                        "username": {"type": "keyword"},
                        "password": {"type": "keyword"},
                        "success": {"type": "boolean"},
                        "timestamp": {"type": "date"},
                    },
                },
                "sql_injection_attempts": {
                    "type": "nested",
                    "properties": {
                        "payload": {"type": "text"},
                        "pattern_matched": {"type": "keyword"},
                        "path": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                    },
                },
                "indexed_at": {"type": "date"},
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
        },
    },
}


class ElasticsearchSink:
    """Manages Elasticsearch operations for the deception-SOC logger."""

    def __init__(self):
        self._client: Optional[AsyncElasticsearch] = None

    async def connect(self):
        """Initialize the Elasticsearch client and create indices."""
        logger.info(f"Connecting to Elasticsearch: {ELASTICSEARCH_HOST}")
        self._client = AsyncElasticsearch(
            hosts=[ELASTICSEARCH_HOST],
            request_timeout=30,
            max_retries=3,
            retry_on_timeout=True,
        )

        # Verify connection
        try:
            info = await self._client.info()
            logger.info(
                f"Connected to Elasticsearch {info['version']['number']}"
            )
        except Exception as e:
            logger.error(f"Could not connect to Elasticsearch: {e}")
            return

        # Create indices
        await self._create_indices()

    async def _create_indices(self):
        """Create all required indices if they don't exist."""
        for index_name, index_config in INDEX_MAPPINGS.items():
            try:
                exists = await self._client.indices.exists(index=index_name)
                if not exists:
                    await self._client.indices.create(
                        index=index_name,
                        body=index_config,
                    )
                    logger.info(f"Created index: {index_name}")
                else:
                    logger.info(f"Index already exists: {index_name}")
            except Exception as e:
                logger.error(f"Error creating index {index_name}: {e}")

    async def index_document(
        self, index: str, document: Dict[str, Any], doc_id: Optional[str] = None
    ) -> Optional[str]:
        """Index a single document."""
        if self._client is None:
            logger.warning("Elasticsearch not connected, skipping indexing")
            return None

        try:
            result = await self._client.index(
                index=index,
                body=document,
                id=doc_id,
            )
            return result.get("_id")
        except Exception as e:
            logger.error(f"Error indexing document to {index}: {e}")
            return None

    async def bulk_index(
        self, index: str, documents: List[Dict[str, Any]]
    ) -> int:
        """Bulk index multiple documents. Returns count of successfully indexed."""
        if self._client is None or not documents:
            return 0

        operations = []
        for doc in documents:
            operations.append({"index": {"_index": index}})
            operations.append(doc)

        try:
            result = await self._client.bulk(body=operations)
            errors = result.get("errors", False)
            if errors:
                error_count = sum(
                    1 for item in result["items"]
                    if "error" in item.get("index", {})
                )
                logger.warning(f"Bulk indexing had {error_count} errors")
                return len(documents) - error_count
            return len(documents)
        except Exception as e:
            logger.error(f"Bulk indexing error: {e}")
            return 0

    async def search(
        self,
        index: str,
        query: Optional[Dict] = None,
        size: int = 50,
        sort: Optional[List] = None,
    ) -> List[Dict]:
        """Search an index and return matching documents."""
        if self._client is None:
            return []

        body = {}
        if query:
            body["query"] = query
        if sort:
            body["sort"] = sort

        try:
            result = await self._client.search(
                index=index,
                body=body,
                size=size,
            )
            return [
                {**hit["_source"], "_id": hit["_id"]}
                for hit in result["hits"]["hits"]
            ]
        except Exception as e:
            logger.error(f"Search error on {index}: {e}")
            return []

    async def aggregate(
        self, index: str, aggs: Dict[str, Any], query: Optional[Dict] = None
    ) -> Dict:
        """Run an aggregation query."""
        if self._client is None:
            return {}

        body = {"size": 0, "aggs": aggs}
        if query:
            body["query"] = query

        try:
            result = await self._client.search(index=index, body=body)
            return result.get("aggregations", {})
        except Exception as e:
            logger.error(f"Aggregation error on {index}: {e}")
            return {}

    async def count(self, index: str) -> int:
        """Get document count for an index."""
        if self._client is None:
            return 0

        try:
            result = await self._client.count(index=index)
            return result.get("count", 0)
        except Exception as e:
            logger.error(f"Count error on {index}: {e}")
            return 0

    async def close(self):
        """Close the Elasticsearch connection."""
        if self._client:
            await self._client.close()
            logger.info("Elasticsearch connection closed")
