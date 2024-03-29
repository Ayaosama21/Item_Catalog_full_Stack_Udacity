from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
 
Base = declarative_base()

class USER(Base):
    __tablename__ = 'user'
   
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)         #to make an email to login or logout
    picture = Column(String(250))           #to make a picture


class Element(Base):
    __tablename__ = 'element'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(USER)


    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id,
       }
 
class ElementItem(Base):
    __tablename__ = 'element_item'


    name =Column(String(80), nullable = False)
    id = Column(Integer, primary_key = True)
    description = Column(String(250))
    element_id = Column(Integer, ForeignKey('element.id'))
    element = relationship(Element)
    #price = Column(String(8))
    #course = Column(String(250))
    user_id = Column(Integer,ForeignKey('user.id'))
    user = relationship(USER)


    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'description'         : self.description,
           'id'         : self.id,
  #         'price'         : self.price,
   #        'course'         : self.course,
       }



engine = create_engine('sqlite:///elements.db')
 

Base.metadata.create_all(engine)