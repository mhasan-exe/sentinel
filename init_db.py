from database import engine, Base
from models import User, SurveyResponse, ExperimentResult

DATABASE_URL="postgresql://neondb_owner:npg_EGpfxeCJ12to@ep-long-scene-avey0zn5-pooler.c-11.us-east-1.aws.neon.tech/neondb?channel_binding=require&sslmode=require"

Base.metadata.create_all(bind=engine)