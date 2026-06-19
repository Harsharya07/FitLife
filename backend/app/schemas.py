from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=6, max_length=128)
    confirm_password: str


class UserLogin(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: int
    username: str
    is_admin: bool = False


class ContactCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    message: str = Field(min_length=1, max_length=2000)


class MessageResponse(BaseModel):
    message: str


class Exercise(BaseModel):
    id: str
    name: str
    image: str
    description: str
    tags: list[str]
    equipment: str
    tip: str
    video_url: str | None = None


class ExerciseCategory(BaseModel):
    id: str
    name: str
    icon: str
    exercises: list[Exercise]


class Article(BaseModel):
    id: str
    title: str
    url: str
    image: str
    author: str
    date: str
    excerpt: str
    categories: list[str]


class Blog(BaseModel):
    id: str
    title: str
    url: str
    image: str
    avatar: str
    rank: str
    mentions: str
    excerpt: str
    category: str


class Recipe(BaseModel):
    id: str
    name: str
    image: str
    description: str
    ingredients: list[str]
    steps: list[str]
    prep_time: str = "15 min"
    calories: str = "320 kcal"


# --- AI ---

class AiStatusResponse(BaseModel):
    configured: bool
    provider: str
    model: str


class UserProfile(BaseModel):
    age: int | None = Field(None, ge=13, le=100)
    gender: str | None = Field(None, max_length=30)
    height_cm: float | None = Field(None, ge=100, le=250)
    weight_kg: float | None = Field(None, ge=30, le=300)
    goal: str | None = Field(None, max_length=100)
    activity_level: str | None = Field(None, max_length=50)
    dietary_preference: str | None = Field(None, max_length=50)
    allergies: str | None = Field(None, max_length=500)
    health_conditions: str | None = Field(None, max_length=500)
    target_calories: int | None = Field(None, ge=800, le=6000)
    workout_days_per_week: int | None = Field(None, ge=1, le=7)
    experience_level: str | None = Field(None, max_length=50)


class ChatMessageRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)


class ChatMessage(BaseModel):
    id: int
    role: str
    content: str
    created_at: str


class ChatResponse(BaseModel):
    reply: str
    message_id: int


class GenerateRequest(BaseModel):
    extra_notes: str | None = Field(None, max_length=2000)
    days: int | None = Field(7, ge=1, le=14)


class AiGenerateResponse(BaseModel):
    content: str
    type: str
    plan_id: int | None = None


# --- Saved plans ---

class SavedPlanCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    plan_type: str = Field(min_length=1, max_length=50)
    content: str = Field(min_length=1, max_length=50000)


class SavedPlan(BaseModel):
    id: int
    title: str
    plan_type: str
    content: str
    created_at: str


# --- Activity / workouts ---

class WorkoutLogCreate(BaseModel):
    exercise_id: str = Field(min_length=1, max_length=100)
    exercise_name: str = Field(min_length=1, max_length=200)
    sets: int | None = Field(None, ge=1, le=50)
    reps: int | None = Field(None, ge=1, le=500)
    weight_kg: float | None = Field(None, ge=0, le=500)
    duration_min: float | None = Field(None, ge=0, le=600)
    notes: str | None = Field(None, max_length=500)


class WorkoutLog(BaseModel):
    id: int
    exercise_id: str
    exercise_name: str
    sets: int | None
    reps: int | None
    weight_kg: float | None
    duration_min: float | None
    notes: str | None
    logged_at: str


class DashboardStats(BaseModel):
    total_workouts: int
    workouts_this_week: int
    current_streak: int
    saved_plans: int
    chat_messages: int
    content_totals: dict[str, int]


class WeeklyActivity(BaseModel):
    date: str
    count: int


class ContactRecord(BaseModel):
    id: int
    name: str
    email: str
    message: str
    created_at: str


class SavedPlanUpdate(BaseModel):
    title: str = Field(min_length=1, max_length=200)


class ActivityFeedItem(BaseModel):
    id: int
    type: str
    title: str
    subtitle: str
    created_at: str


class ExercisePR(BaseModel):
    exercise_id: str
    exercise_name: str
    best_sets: int | None
    best_reps: int | None
    best_weight_kg: float | None
    total_sessions: int


class MonthlyActivity(BaseModel):
    date: str
    count: int


# --- Body metrics ---

class BodyMetricCreate(BaseModel):
    weight_kg: float | None = Field(None, ge=20, le=300)
    body_fat_pct: float | None = Field(None, ge=1, le=60)
    waist_cm: float | None = Field(None, ge=40, le=200)
    notes: str | None = Field(None, max_length=500)


class BodyMetric(BodyMetricCreate):
    id: int
    logged_at: str


# --- Workout sessions ---

class SessionStart(BaseModel):
    name: str = Field(default="Workout Session", max_length=200)


class SessionExerciseLog(WorkoutLogCreate):
    pass


class WorkoutSession(BaseModel):
    id: int
    name: str
    status: str
    started_at: str
    ended_at: str | None
    notes: str | None
    exercise_count: int = 0


# --- Goals ---

class GoalCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    goal_type: str = Field(min_length=1, max_length=50)
    target_value: float = Field(gt=0)
    unit: str | None = Field(None, max_length=30)
    deadline: str | None = None


class Goal(GoalCreate):
    id: int
    current_value: float
    completed: bool
    created_at: str


class GoalUpdate(BaseModel):
    current_value: float | None = None
    completed: bool | None = None


# --- Badges ---

class Badge(BaseModel):
    badge_id: str
    title: str
    description: str
    earned_at: str | None = None


# --- Water ---

class WaterLogCreate(BaseModel):
    glasses: int = Field(default=1, ge=1, le=20)


class WaterToday(BaseModel):
    glasses: int
    goal: int = 8


# --- Favorites ---

class FavoriteCreate(BaseModel):
    item_type: str = Field(min_length=1, max_length=30)
    item_id: str = Field(min_length=1, max_length=100)


class Favorite(FavoriteCreate):
    id: int
    created_at: str


# --- Shares ---

class ShareResponse(BaseModel):
    share_token: str
    share_url: str


class PublicPlan(BaseModel):
    title: str
    plan_type: str
    content: str
    created_at: str


# --- Password reset ---

class ForgotPasswordRequest(BaseModel):
    username: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=6, max_length=128)
    confirm_password: str


# --- Notifications ---

class Notification(BaseModel):
    id: int
    type: str
    title: str
    body: str
    read: bool
    created_at: str


# --- Calendar ---

class CalendarDay(BaseModel):
    date: str
    workouts: int
    water_glasses: int


# --- Export ---

class ExportData(BaseModel):
    profile: dict | None
    workouts: list
    plans: list
    metrics: list
    goals: list
    badges: list


# --- Admin analytics ---

class AdminAnalytics(BaseModel):
    total_users: int
    total_workouts: int
    total_plans: int
    total_ai_chats: int
    signups_last_7_days: int


class BlogReactionResponse(BaseModel):
    blog_id: str
    count: int
    user_reacted: bool


class ForgotPasswordResponse(BaseModel):
    message: str
    reset_token: str | None = None
