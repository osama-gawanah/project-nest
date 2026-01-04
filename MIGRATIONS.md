# Database Migrations

## تشغيل Migrations

لتشغيل migrations وإنشاء/تحديث جداول قاعدة البيانات:

```bash
npm run migration:run
```

## إنشاء Migration جديد

1. أنشئ ملف جديد في `src/migrations/` بالصيغة:
   `YYYYMMDDHHMMSS-description.ts`

2. استخدم هذا القالب:

```typescript
import { QueryInterface, DataTypes } from 'sequelize';

export async function up(queryInterface: QueryInterface): Promise<void> {
  // كود لإنشاء/تعديل الجدول
}

export async function down(queryInterface: QueryInterface): Promise<void> {
  // كود للتراجع عن التغييرات
}
```

## ملاحظات

- Migrations يتم تشغيلها تلقائياً عند بدء التطبيق في بيئة التطوير (إذا كان `NODE_ENV !== 'production'`)
- يمكنك أيضاً تشغيلها يدوياً باستخدام `npm run migration:run`
- يتم تتبع Migrations المنفذة في جدول `SequelizeMeta`

