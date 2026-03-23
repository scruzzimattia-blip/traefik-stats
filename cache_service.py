import os
import json
import redis
import logging
from functools import wraps
from typing import Any, Callable, Optional, Union
import hashlib

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", os.getenv("REDIS_CACHE_URL", "redis://redis:6379/0"))

_redis_client: Optional[redis.Redis] = None
_redis_available = False

def get_redis_client() -> Optional[redis.Redis]:
    global _redis_client, _redis_available
    if _redis_client is None:
        try:
            _redis_client = redis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=2, socket_timeout=2)
            _redis_client.ping()
            _redis_available = True
            logger.info("Redis cache connected")
        except redis.ConnectionError:
            _redis_available = False
            _redis_client = None
            logger.debug("Redis unavailable, using fallback")
        except Exception as e:
            logger.warning(f"Redis connection error: {e}")
            _redis_available = False
            _redis_client = None
    return _redis_client if _redis_available else None

def _make_cache_key(prefix: str, *args, **kwargs) -> str:
    key_parts = [prefix]
    for arg in args:
        key_parts.append(str(arg))
    for k, v in sorted(kwargs.items()):
        key_parts.append(f"{k}={v}")
    key_str = ":".join(key_parts)
    if len(key_str) > 200:
        hash_suffix = hashlib.md5(key_str.encode()).hexdigest()[:16]
        key_str = f"{prefix}:{hash_suffix}"
    return key_str

def _serialize(value: Any) -> str:
    try:
        return json.dumps(value, default=str)
    except:
        return str(value)

def _deserialize(value: Optional[str]) -> Any:
    if value is None:
        return None
    try:
        return json.loads(value)
    except:
        return value

class CacheService:
    DEFAULT_TTL = {
        "short": 60,
        "medium": 300,
        "long": 3600,
        "very_long": 86400,
    }
    
    @classmethod
    def get(cls, key: str) -> Optional[Any]:
        client = get_redis_client()
        if not client:
            return None
        try:
            value = client.get(key)
            return _deserialize(value)
        except Exception as e:
            logger.debug(f"Cache get error: {e}")
            return None
    
    @classmethod
    def set(cls, key: str, value: Any, ttl: int = 300) -> bool:
        client = get_redis_client()
        if not client:
            return False
        try:
            client.setex(key, ttl, _serialize(value))
            return True
        except Exception as e:
            logger.debug(f"Cache set error: {e}")
            return False
    
    @classmethod
    def delete(cls, key: str) -> bool:
        client = get_redis_client()
        if not client:
            return False
        try:
            client.delete(key)
            return True
        except Exception as e:
            logger.debug(f"Cache delete error: {e}")
            return False
    
    @classmethod
    def delete_pattern(cls, pattern: str) -> int:
        client = get_redis_client()
        if not client:
            return 0
        try:
            keys = client.keys(pattern)
            if keys:
                return client.delete(*keys)
            return 0
        except Exception as e:
            logger.debug(f"Cache delete pattern error: {e}")
            return 0
    
    @classmethod
    def clear_all(cls) -> bool:
        client = get_redis_client()
        if not client:
            return False
        try:
            client.flushdb()
            return True
        except Exception as e:
            logger.debug(f"Cache clear error: {e}")
            return False
    
    @classmethod
    def exists(cls, key: str) -> bool:
        client = get_redis_client()
        if not client:
            return False
        try:
            return bool(client.exists(key))
        except:
            return False
    
    @classmethod
    def get_or_set(cls, key: str, factory: Callable[[], Any], ttl: int = 300) -> Any:
        cached = cls.get(key)
        if cached is not None:
            return cached
        value = factory()
        cls.set(key, value, ttl)
        return value

def cached(ttl: int = 300, key_prefix: str = "cache"):
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache_key = _make_cache_key(f"traefik_stats:{key_prefix}:{func.__name__}", *args, **kwargs)
            
            cached_value = CacheService.get(cache_key)
            if cached_value is not None:
                return cached_value
            
            result = func(*args, **kwargs)
            
            if result is not None:
                CacheService.set(cache_key, result, ttl)
            
            return result
        return wrapper
    return decorator

def invalidate_cache(prefix: str = "traefik_stats:*"):
    return CacheService.delete_pattern(prefix)
