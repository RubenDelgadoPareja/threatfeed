"""Declarative base shared by every model (~ Rails' ApplicationRecord)."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
