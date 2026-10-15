# Crypto Fraud Tracer — أداة تتبع احتيال العملات الرقمية

**العربية أولًا · English below**

أداة مجانية مفتوحة المصدر تساعد ضحايا احتيال العملات الرقمية على فهم أين ذهب مالهم، وتجهيز أدلتهم ورسائلهم للمنصات والشرطة والمحامي. تعمل على حاسوبك، وبياناتك لا تغادره (تتصل فقط بمزوّدي البلوكشين العامين لقراءة المعاملات).

## ماذا تفعل
- تبدأ من **رقم معاملة الدفع**، أو من **عنوان المحتال** فتختار دفعتك من قائمة، فيُتتبَّع مالك وحده.
- تعطيك **«خيطك الأول»** بلغة بسيطة، وتتتبع المال على 11 شبكة (بيتكوين وإيثريوم وTRON وثمانٍ تجريبية) مع **خريطة** تفاعلية بسبع لغات.
- تشخّص العنوان المزدحم: **يشبه منصة أم عنوان تجميع؟** بمؤشرات مشروحة بأرقامها.
- تكتب **رسائل جاهزة** للمنصات وإشعارًا لـTether وبلاغًا مرتبًا للشرطة، وتحفظ الأدلة بسلسلة تجزئة (SHA-256).
- تفحص **قبل أن تدفع**: «توقف» أو «حذر» أو «لا مؤشرات» (ولا تقول «آمن» أبدًا).

## الشبكات المدعومة
جرّبنا الشبكات التالية على بيانات حقيقية بتاريخ 15 أكتوبر 2026 (`python live_check.py`):

| الشبكة | الحالة |
|---|---|
| Bitcoin، Ethereum، TRON | تعمل على بيانات حقيقية (التتبع والتحقق من مصدر ثانٍ) |
| Litecoin، Solana | تعمل على بيانات حقيقية (قراءة الكتل والمعاملات) |
| Dogecoin، Bitcoin Cash | تعمل عبر Blockchair؛ لم يُفحص إلا ارتفاع آخر كتلة، فتبقى **تجريبية** |
| Polygon وArbitrum | **تعمل** مع مفتاح Etherscan مجاني في `ETHERSCAN_API_KEY` (جُرّبت على بيانات حقيقية في 15 أكتوبر 2026) |
| BNB Chain وBase | العقد تعمل، لكن سجل العمليات غير متاح في الخطة المجانية من Etherscan (يتطلب خطة مدفوعة)، فتبقى **تجريبية** ولا تعتمد عليها |

شغّل `python live_check.py` على جهازك لترى الحالة عندك (وأرسل التقرير إن ظهر FAIL).

## اللغات
الواجهة بسبع لغات: العربية، English، Español، Français، Türkçe، Русский، فارسی (قائمة اللغة أعلى الصفحة؛ العربية والفارسية من اليمين لليسار). الترجمات في `i18n/translations.tsv`؛ بعد أي تعديل على نصوص `index.html` شغّل `python i18n_build.py --check` ثم `--write`.
**ما بقي بالعربية فقط:** بقية التقرير الطويل والرسائل الجاهزة للمنصات والشرطة وملفات القضية. أما «خيطك الأول» و«تشخيص العنوان» وقائمة المدفوعات فتصدر بالإنجليزية لمن اختار الإنجليزية أو الإسبانية أو الفرنسية أو التركية أو الروسية. ترجمات الإسبانية والفرنسية والتركية والروسية والفارسية كُتبت آليًا وتحتاج مراجعة ناطق بها قبل النشر الواسع.

## إلى أي منصة وصل المال؟ وماذا عن الخلط؟
- **`platform_finder.py`** (ويظهر في التقرير تلقائيًا): يرتّب العناوين التي تشبه محفظة منصة بمؤشرات مشروحة: وسم معروف، أو عناوين إيداع تحوّل كل ما استلمته إلى عنوان واحد خلال أيام (نمط التجميع في محفظة المنصة)، أو عنوان كثير النشاط. المراتب: معروفة، اسم مستنتج، مرجّحة، محتملة. **لا يخترع اسمًا**: الاسم يأتي من التصنيفات التي استوردتها من المصادر الرسمية (إثبات احتياطيات المنصات) أو أكدتها بنفسك. يقول أين دخل المال إلى خدمة، لا ما جرى داخلها.
- **`mix_check.py`**: يكشف أين دخل التتبع إلى خلّاط أو CoinJoin وما آخر عنوان قبله. **لا يدّعي تتبع المال عبر الخلط**: في CoinJoin بخمسة مخارج متساوية، مالك واحد من خمسة ولا يمكن معرفة أيها، وأفضل احتمال لتخمين هو 1/5. والمطابقة بالمبلغ والوقت تعطي قائمة مرشحين بثقة «منخفضة جدًا» قد تضم بريئًا، فهي خيط للشرطة وليست دليلًا ولا اتهامًا. ويُذكر الخلط نفسه في بلاغ الشرطة.

## تسميات المنصات
البرنامج لا يعرف اسم المنصة إلا من تسمية موثّقة. نرفق `labels_seed_sources.csv`: 30 عنوانًا نشرتها منصتا CEX.IO وCrypto.com على موقعيهما الرسميين مع روابط المصدر (استوردها بـ `python labels_tool.py import-csv labels_seed_sources.csv --source official --name-col name`). أضف قضاياك المؤكدة في `my_cases.csv`، واستورد بلاغات حكومية بـ `labels_tool.py import-text FILE --source "..."` (يتجاهل العناوين الخاطئة بفحص checksum). التحديث الدوري: `labels_tool.py sync` (انظر `schedule_labels.md`). لا تُنشر أي عناوين لم نتحقق منها.

## ما لا تفعله (مهم)
- **ليست خدمة استرداد** ولا تعد بأي استرداد أو تجميد أو كشف هوية، ولا تذكر اسم أي شخص.
- النتائج مؤشرات احتمالية من بيانات عامة قد تكون ناقصة. لا تعتمد عليها وحدها في قرار قانوني؛ استشر محاميًا.
- **احذر من «مستردي الأموال»**: كل من يطلب رسومًا مسبقة أو مفتاحك الخاص أو عبارة الاسترداد محتال. هذه الأداة لا تطلب شيئًا من ذلك.
- جُرّبت على الشبكات الحقيقية بفحص محدود (انظر الجدول)؛ إن لاحظت خطأ فأبلغ عنه (انظر «الإبلاغ عن مشكلة»).

## التشغيل (3 دقائق)
اقرأ **[START-HERE-AR.md](START-HERE-AR.md)** (شرح لغير المبرمجين). باختصار: ثبّت Python 3.8+، ثم `python serve.py` وافتح `http://127.0.0.1:8765`. على ويندوز انقر مرتين على `run.bat`.
الدليل الكامل: **[GUIDE-AR.md](GUIDE-AR.md)**. للتأكد أن الملفات سليمة: `python selftest.py` (يجب أن يظهر ALL CHECKS PASSED).

## الإبلاغ عن مشكلة
شغّل `python capture.py record rec -- investigate.py btc ADDRESS --live` ثم أرفق `rec.zip` (يحذف مفاتيح API، لكنه يحوي العناوين التي بحثت عنها، فراجع `manifest.json` قبل الإرسال).

## الترخيص
MIT (انظر LICENSE). المساهمات مرحّب بها.

---

## English
A free, open-source tool that helps victims of cryptocurrency fraud see where their funds went and prepare evidence and letters for exchanges, police and lawyers. It runs on your computer; it only calls public blockchain data providers.

- Start from your payment transaction, or from the scammer's address and **pick your own payment** so only your funds are traced.
- Plain-language **"first lead"**, tracing on 11 networks with an interactive **map**, and a **platform-wallet vs collection-address** diagnosis with every signal explained.
- Ready-to-send letters, hash-chained evidence ledger, and a **pre-payment check** that never says "safe".

**Not a recovery service. No promises. Names no one.** Results are probabilistic indicators from public data. Beware of "recovery services" that ask for fees or your seed phrase: they are scams. Run: install Python 3.8+, then `python serve.py` and open http://127.0.0.1:8765 (or double-click `run.bat` on Windows). Self-check: `python selftest.py`. License: MIT.

**Networks.** Tested on real data on 15 Oct 2026 (`python live_check.py`): Bitcoin, Ethereum, TRON, Litecoin and Solana work. Polygon and Arbitrum work with a free Etherscan key in `ETHERSCAN_API_KEY`. Dogecoin and Bitcoin Cash work through Blockchair (only the chain tip was checked, so they stay **experimental**). BNB Chain and Base: the RPC nodes work, but address history is not available on Etherscan's free plan (and Blockscout blocks scripts), so they stay **experimental**.

**Platform names.** The tool names a platform only from a documented label. `labels_seed_sources.csv` ships 30 addresses published by CEX.IO and Crypto.com on their own official pages (source URL on every row). Add your confirmed cases, import government notices with `labels_tool.py import-text`, and keep sources fresh with `labels_tool.py sync` (see `schedule_labels.md`).
