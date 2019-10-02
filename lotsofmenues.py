from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
 
from database_setup import Restaurant, Base, MenuItem
 
engine = create_engine('sqlite:///elementmenu.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine
 
DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

#create a user
USER1 = USER(name="Aya Osama", email="ayao21684@gmail.com",
             picture='https://www.google.com/search?q=image+of+human+profile&rlz=1C1JZAP_arEG867EG867&sxsrf=ACYBGNSx0aibw8DMjtJ_Ar2FskrOUpW9zg:1569887970523&tbm=isch&source=iu&ictx=1&fir=99IQlsFIGr09sM%253A%252CCHYgWwE5-0nTXM%252C_&vet=1&usg=AI4_-kQmRqJ1IwWdqMaRIg3uaVwnv4FqhQ&sa=X&ved=2ahUKEwiRwMe24PnkAhURohQKHY32AGsQ9QEwAHoECAkQBg#imgrc=99IQlsFIGr09sM:')
session.add(USER1)
session.commit()

#Menu for football
element1 = Element(user_id=1, name = "football")

session.add(element1)
session.commit()


elementItem1 = ElementItem(user_id=1, name = "buy a ball,t-shirt and shoes", description = "you can practise your sport in outdoors ",  element = element1)

session.add(elementItem1)
session.commit()

elementItem2 = ElementItem(user_id=1, name = "technique of playing", description = "shooting a ball with player's foot", element = element1)

session.add(elementItem2)
session.commit()

#Menu for basketball
element2 = Element(user_id=1, name = "BASKETBALL")

session.add(element2)
session.commit()


elementItem1 = ElementItem(user_id=1, name = "buy a ball of basketball and clothes which belongs to this sport", description = "it's about a leg fitness for our player", element = element2)

session.add(elementItem1)
session.commit()

elementItem2 = ElementItem(user_id=1, name = "basketball is one of famous sports",
                     description = "ghj", element = element2)

session.add(elementItem2)
session.commit()

#Menu for karate
element1 = Element(user_id=1, name="it's a sport which you can fight with another person", description="it's a very important sport",
                    element=element1)

session.add(elementItem1)
session.commit()

print "added menu items!"
