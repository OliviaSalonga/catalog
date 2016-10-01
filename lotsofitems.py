from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Item, Category, User

import datetime

engine = create_engine('sqlite:///catalog.db')

# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
# Base.metadata.bind = engine
 
DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

#User
user1 = User(name="Olivia Gmail",email="olivia.salonga@gmail.com")
session.add(user1)
session.commit()

user2 = User(name="Olivia Facebook",email="alius181@yahoo.com")
session.add(user2)
session.commit() 

#Category
category1 = Category(name="Soccer")
session.add(category1)
session.commit()

category2 = Category(name="Basketball")
session.add(category2)
session.commit()

category3 = Category(name="Snowboarding")
session.add(category3)
session.commit()

dateTimeNow = datetime.datetime.now()

#Menu for UrbanBurger
item1 = Item(name = "Soccer Ball", description="an inflated ball used in playing soccer",
	category=category1, user = user1)
session.add(item1)
session.commit()

item2 = Item(name = "Snowboard", 
	description="Snowboards are boards that are usually the width of one's foot longways, with the ability to glide on snow.[1] Snowboards are differentiated from monoskis by the stance of the user. In monoskiing, the user stands with feet inline with direction of travel (facing tip of monoski/downhill) (parallel to long axis of board), whereas in snowboarding, users stand with feet transverse (more or less) to the longitude of the board. Users of such equipment may be referred to as snowboarders. Commercial snowboards generally require extra equipment such as bindings and special boots which help secure both feet of a snowboarder, who generally rides in an upright position.[1] These types of boards are commonly used by people at ski hills or resorts for leisure, entertainment, and competitive purposes in the activity called snowboarding.",
	category=category3, user = user2)
session.add(item2)
session.commit()

print "added menu items!"

