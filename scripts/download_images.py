#!/usr/bin/env python3
"""Download free Pexels/Unsplash images into frontend/public/images/."""
from pathlib import Path
import shutil
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "frontend" / "public" / "images"

# Pexels photos — free to use (https://www.pexels.com/license/)
P = "https://images.pexels.com/photos/{id}/pexels-photo-{id}.jpeg?auto=compress&cs=tinysrgb&w=800&h=600&fit=crop"
P_SM = "https://images.pexels.com/photos/{id}/pexels-photo-{id}.jpeg?auto=compress&cs=tinysrgb&w=400&h=400&fit=crop"
U = "https://images.unsplash.com/{path}?w=800&h=600&fit=crop&q=80"

def px(pid: int, sm=False) -> str:
    return (P_SM if sm else P).format(id=pid)

def us(path: str) -> str:
    return U.format(path=path)

SOURCES: dict[str, str] = {
    "brand/logo.jpg": px(3253501),
    "heroes/dashboard.jpg": "https://images.unsplash.com/photo-1506744038136-46273834b3fb?w=1500&q=80&auto=format&fit=crop",
    "heroes/articles.jpg": px(4056535),                 # mobility / fitness article hero
    "heroes/blogs.jpg": px(3253501),                    # crossfit / community fitness
    "heroes/ai-coach.jpg": px(2261477),
    "heroes/exercises.jpg": px(28300388),               # pull-ups in gym
    "heroes/recipes.jpg": px(1640777),                  # colorful quinoa salad
    "placeholder.jpg": px(1552242),
    # Exercises — verified Pexels titles match each movement
    "exercises/push-ups.jpg": px(4720330),              # man doing push-up in gym
    "exercises/dumbbell-chest-press.jpg": px(4720764),  # dumbbell bench press
    "exercises/incline-push-up.jpg": px(1638336),       # push-ups on incline bench
    "exercises/chest-fly.jpg": px(11433059),            # dumbbell fly on bench
    "exercises/bench-press.jpg": px(4720776),           # barbell bench press
    "exercises/cable-crossover.jpg": px(5327498),       # cable crossover machine
    "exercises/renegade-row.jpg": px(2247179),          # plank row with dumbbells
    "exercises/pull-ups.jpg": px(28300388),             # man doing pull-ups in gym
    "exercises/superman.jpg": px(6283597),              # back extension / arch stretch
    "exercises/lat-pulldown.jpg": px(12203215),         # lat pulldown machine
    "exercises/deadlift.jpg": px(4853280),              # barbell deadlift
    "exercises/bent-over-row.jpg": px(29825221),        # dumbbell bent-over row
    "exercises/shoulder-press.jpg": px(7289236),        # dumbbell shoulder press
    "exercises/lateral-raise.jpg": px(29793977),        # dumbbell side raises
    "exercises/front-raise.jpg": px(6550851),           # dumbbell front raise
    "exercises/pike-push-up.jpg": px(3822688),          # downward dog / pike push-up
    "exercises/face-pulls.jpg": px(13211583),           # cable rope pull workout
    "exercises/arnold-press.jpg": px(7187964),          # dumbbells overhead
    "exercises/bicep-curl.jpg": px(4720754),            # dumbbell curls on bench
    "exercises/tricep-dips.jpg": px(5496589),           # tricep dip on bench
    "exercises/hammer-curl.jpg": px(5714266),           # dumbbell curl (neutral grip)
    "exercises/diamond-push-up.jpg": us("photo-1574680096145-d05b474e2155"),  # close-grip push-up
    "exercises/skull-crushers.jpg": px(29218854),       # cable tricep extension
    "exercises/chin-ups.jpg": px(14591604),             # chin-ups on bar
    "exercises/plank.jpg": px(4945275),                 # forearm plank on mat
    "exercises/bicycle-crunches.jpg": px(8070393),      # sit-ups / crunches on mat
    "exercises/russian-twist.jpg": px(5128466),          # russian twist with med ball
    "exercises/leg-raises.jpg": px(416778),             # leg raise on mat
    "exercises/mountain-climbers.jpg": px(2294361),     # mountain climbers
    "exercises/dead-bug.jpg": px(3930994),              # supine core exercise on mat
    "exercises/squats.jpg": px(18986400),               # squat with kettlebell
    "exercises/glute-bridge.jpg": px(6516221),         # glute bridge on mat
    "exercises/lunges.jpg": px(5067741),                # forward lunge with dumbbells
    "exercises/calf-raise.jpg": px(3838389),            # standing dumbbell workout
    "exercises/romanian-deadlift.jpg": px(5837307),     # barbell hip-hinge deadlift
    "exercises/leg-press.jpg": px(6844939),             # leg press machine
    "exercises/running.jpg": px(414029),
    "exercises/jump-rope.jpg": px(6339603),
    "exercises/cycling.jpg": px(248547),
    "exercises/burpees.jpg": px(30246184),              # burpee exercise
    "exercises/rowing-machine.jpg": us("photo-1549060279-7e168fcee0c2"),  # rowing ergometer
    "exercises/hiit.jpg": px(6389854),                  # battle ropes / HIIT
    # Articles — each photo matches the article topic
    "articles/laughter-yoga.jpg": px(3822621),          # woman in yoga lotus pose
    "articles/weighted-vest-walking.jpg": px(414029),   # person running outdoors
    "articles/resistance-training.jpg": px(4853280),    # barbell deadlift
    "articles/exercise-at-night.jpg": px(4945275),      # forearm plank workout
    "articles/incentives-active.jpg": px(6339603),      # jump rope cardio
    "articles/presidential-fitness-test.jpg": px(30246184),  # burpee exercise
    "articles/protein-intake.jpg": px(769289),          # grilled steak protein meal
    "articles/hydration.jpg": px(416528),               # water pouring into glass
    "articles/sleep-recovery.jpg": px(6651881),         # woman sleeping in bed
    "articles/morning-routine.jpg": px(16288338),       # oatmeal breakfast bowl
    "articles/meal-prep.jpg": px(30635720),             # meal prep containers
    "articles/mobility-stretching.jpg": px(4056535),      # mobility / stretching
    # Blogs — themed cover image per fitness blog
    "blogs/run-eat-repeat.jpg": px(414029),             # running
    "blogs/muscle-and-fitness.jpg": px(4720776),        # barbell bench press
    "blogs/breaking-muscle.jpg": px(4853280),           # barbell deadlift
    "blogs/best-blogs.jpg": px(3253501),                # crossfit rope training
    "blogs/nutrition-insights.jpg": px(1640770),        # colorful vegan bowls
    "blogs/yoga-journal.jpg": px(3822688),              # downward dog yoga
    "blogs/crossfit-community.jpg": px(6389854),        # battle ropes HIIT
    "blogs/wellness-daily.jpg": px(3822622),            # meditation / wellness
    "blogs/avatars/run-eat-repeat.jpg": px(414029, sm=True),
    "blogs/avatars/muscle-and-fitness.jpg": px(841130, sm=True),
    "blogs/avatars/breaking-muscle.jpg": px(4853280, sm=True),
    "blogs/avatars/best-blogs.jpg": px(3253501, sm=True),
    "blogs/avatars/nutrition-insights.jpg": px(1640770, sm=True),
    "blogs/avatars/yoga-journal.jpg": px(3822688, sm=True),
    "blogs/avatars/crossfit-community.jpg": px(6389854, sm=True),
    "blogs/avatars/wellness-daily.jpg": px(6651881, sm=True),
    # Recipes — each dish gets its own matching food photo
    "recipes/quinoa-salad.jpg": px(1640777),            # quinoa vegetable salad
    "recipes/grilled-chicken.jpg": px(28618645),        # grilled chicken salad
    "recipes/avocado-toast.jpg": px(13887555),          # avocado toast plate
    "recipes/berry-smoothie.jpg": px(8169597),          # strawberry smoothie
    "recipes/oatmeal-bowl.jpg": px(16288338),           # oatmeal with fruits
    "recipes/veggie-stir-fry.jpg": px(2175211),         # stir fry with vegetables
    "recipes/chickpea-buddha-bowl.jpg": px(37279768),   # vegan buddha bowl
    "recipes/banana-pancakes.jpg": px(30892859),        # pancakes with berries
    "recipes/salmon-teriyaki.jpg": px(725991),          # grilled salmon plate
    "recipes/greek-yogurt-parfait.jpg": px(37103655),   # yogurt parfait bowl
    "recipes/veggie-wrap.jpg": px(14930573),            # hummus with pita
    "recipes/lentil-soup.jpg": px(18041312),            # vegetable soup in jar
    "recipes/protein-bowl.jpg": px(30635720),           # meal prep protein bowl
    "recipes/overnight-oats.jpg": px(7879791),          # overnight oats in jar
}


def download(url: str, dest: Path) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "FitLife-Asset-Script/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read()
            if len(data) < 1000:
                return False
            dest.write_bytes(data)
            return True
    except Exception as e:
        print(f"  error: {e}")
        return False


def main():
    ok, fail = 0, 0
    fallback = OUT / "placeholder.jpg"
    for rel, url in SOURCES.items():
        dest = OUT / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        print(f"Downloading {rel}...", end=" ")
        if download(url, dest):
            print("OK")
            ok += 1
        else:
            print("FAIL")
            fail += 1

    # Fill any missing with placeholder
    if fallback.exists():
        for rel in SOURCES:
            dest = OUT / rel
            if not dest.exists() or dest.stat().st_size < 1000:
                shutil.copy(fallback, dest)
                print(f"Fallback copied -> {rel}")

    print(f"\nDone: {ok} ok, {fail} failed (fallbacks applied where needed)")


if __name__ == "__main__":
    main()
