# نشر VulnGraph بشكل احترافي على GitHub وGitHub Pages

## 1. المشروع منفصل عن CyberGuard

1. أنشئي مستودعًا جديدًا باسم `VulnGraph` من `https://github.com/new`.
2. اختاري **Public** إذا كنتِ تريدين عرضه في ملف أعمالك.
3. **لا تنشئي README أو .gitignore أو License من GitHub**؛ كلها موجودة ضمن هذه الحزمة.
4. ارفعي **محتويات مجلد VulnGraph** مع مجلدات `.github` و`docs` و`static` و`vulngraph`، وليس ZIP وحده.
5. تابعي تبويب **Actions**؛ سيتأكد من الاختبارات على عدة إصدارات Python ومن إنشاء صورة Docker.

**وصف المستودع المقترح:**

> Explainable software supply-chain vulnerability intelligence with CycloneDX, OSV, EPSS, CISA KEV, FastAPI, and interactive dependency mapping.

**Topics:** `cybersecurity`, `vulnerability-management`, `sbom`, `appsec`, `python`, `fastapi`, `osv`, `epss`, `cyclonedx`, `software-supply-chain`.

## 2. تحويل الاستعراض إلى صفحة تفاعلية

لأن المشروع يحتوي على نسخة **تجريبية ثابتة** داخل `docs/index.html`، يمكن نشر واجهته مباشرة باستخدام GitHub Pages، دون خادم Python.

1. بعد رفع الملفات ادخلي صفحة المستودع → **Settings** → **Pages**.
2. في **Build and deployment** اختاري **Deploy from a branch**.
3. اختاري Branch = `main` وFolder = `/docs`، ثم **Save**.
4. بعد نجاح إعداد Pages، يظهر لك رابط الواجهة التجريبية في نفس الصفحة.
5. ضعي الرابط في قسم About بالمستودع وفي ملف السيرة الذاتية إذا أردتِ.

**ضروري:** صفحة GitHub Pages هذه **عرض تفاعلي ببيانات خيالية** فقط: تغيير الأولويات والبحث والتفاصيل والتصدير تعمل، أما رفع ملفات SBOM والتحقق المباشر من OSV فلا يعملان فيها. تحتاج هذه المزايا إلى تشغيل خادم FastAPI من النسخة الكاملة.

## 3. تمييز الروابط في السيرة الذاتية

- **Source code:** رابط مستودع GitHub.
- **Interactive demo:** رابط GitHub Pages الذي يظهر بعد إعداده.
- **Full analysis API:** لا تضعي رابطًا عامًا قبل استضافة آمنة ومصادقة مناسبة.

لا تصفي المشروع بأنه ذكاء اصطناعي مدرّب أو يستخدم استغلال الثغرات؛ قوته في الجمع المدروس للأدلة وتفسير الأولوية، وليس كشف الثغرات المجهولة بنفسه.
