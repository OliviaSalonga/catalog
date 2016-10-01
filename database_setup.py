from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, Table, PrimaryKeyConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship 
from sqlalchemy import create_engine
import datetime
 
Base = declarative_base()

class User(Base):
	__tablename__ = 'user'
	
	id = Column(Integer, primary_key=True)
	email = Column(String(80), nullable=False, unique=True)
	name = Column(String(80))
	
class Category(Base):
	__tablename__ = 'category'
	
	id = Column(Integer, primary_key=True)
	name = Column(String(80), nullable=False, unique=True)
	
	@property
	def serialize(self):
		"""Return object data in easily serializeable format"""
		return {
			'name'         : self.name,
			'id'           : self.id,
		}
 
item_category = Table('item_category', Base.metadata,
	Column('category_id', Integer, ForeignKey('category.id'), nullable = False),
	Column('item_name', String(80), ForeignKey('item.name'), nullable = False),
	Column('item_id', Integer, ForeignKey('item.id'), nullable = False),
	PrimaryKeyConstraint('category_id','item_name'))
 
class Item(Base):
	__tablename__ = 'item'
	
	name =Column(String(80), nullable = False)
	id = Column(Integer, primary_key = True)
	description = Column(String(250), nullable = False)
	created_date = Column(DateTime, default=datetime.datetime.utcnow)
	category_id = Column(Integer,ForeignKey('category.id'), nullable = False)
	category = relationship(Category)
	user_id = Column(Integer,ForeignKey('user.id'), nullable = False)
	user = relationship(User)
	
	@property
	def serialize(self):
		"""Return object data in easily serializeable format"""
		return {
           'name': self.name,
           'description': self.description,
           'id': self.id,
		   'created_date': self.created_date,
           'category_id': self.category_id,
           'user_id': self.user_id,
		   }

engine = create_engine('sqlite:///catalog.db')
 

Base.metadata.create_all(engine)
