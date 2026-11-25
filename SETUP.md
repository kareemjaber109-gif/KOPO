# دليل تشغيل مشروع KOPO (Setup Guide)

هذا الدليل يوضح جميع المكتبات والخطوات اللازمة لتشغيل المشروع (الباك إند والفرونت إند) على أي جهاز جديد.

---

## 1. المتطلبات الأساسية (Prerequisites)
- **Python:** إصدار 3.10 أو 3.11 أو 3.12
- **Node.js:** إصدار 18 أو 20 أو أحدث (مع npm)
- **Git**

---

## 2. تثبيت مكتبات الباك إند والذكاء الاصطناعي (Python Backend)

افتح التيرمينال في المجلد الرئيسي للمشروع ونفذ:

```bash
# إنشاء بيئة افتراضية (اختياري ومفضل)
python -m venv .venv

# تفعيل البيئة:
# على Windows:
.venv\Scripts\activate
# على Linux / Mac:
source .venv/bin/activate

# تثبيت جميع المكتبات بضغطة واحدة:
pip install -r requirements.txt
```

### قائمة مكتبات البايثون في `requirements.txt`:
* **الموديلات والذكاء الاصطناعي:** `torch` (LSTM & Autoencoder), `xgboost`, `scikit-learn` (Random Forest & Isolation Forest), `numpy`, `pandas`, `scipy`, `joblib`, `imbalanced-learn`.
* **السيرفر والـ API:** `fastapi`, `uvicorn[standard]`, `pydantic`, `pydantic-settings`, `python-multipart`.
* **قاعدة البيانات:** `sqlalchemy`, `aiosqlite`, `greenlet`.
* **الخدمات المساعدة:** `loguru`, `httpx`, `requests`, `python-dotenv`, `tqdm`.

---

## 3. تثبيت مكتبات واجهة المستخدم (React Frontend)

افتح تيرمينال جديد وادخل مجلد الفرونت إند:

```bash
cd frontend
npm install
```

### قائمة مكتبات الفرونت إند في `frontend/package.json`:
* **React & Dom:** `react`, `react-dom`, `react-router-dom` (التنقل بين الصفحات).
* **الأيقونات والتصميم:** `lucide-react`.
* **الرسومات البيانية:** `recharts`.
* **التواريخ والتحقق:** `date-fns`, `zod`.
* **أدوات التطوير:** `vite`, `typescript`.

---

## 4. تشغيل المشروع (Running the Project)

### أولاً: تشغيل الباك إند
من المجلد الرئيسي للمشروع:
```bash
python -m uvicorn src.api.main:app --port 8000 --reload
```
* الرابط: [http://127.0.0.1:8000](http://127.0.0.1:8000)
* توثيق Swagger: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### ثانياً: تشغيل الفرونت إند
من داخل مجلد `frontend`:
```bash
cd frontend
npm run dev
```
* الرابط: [http://localhost:5173](http://localhost:5173)
