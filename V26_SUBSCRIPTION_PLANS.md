# V26 – Subscription Plans & School Billing Configuration

V26 adds configurable subscription plans without connecting a payment gateway.

## Default plans
- 30-Day Trial: ₦0, 30 days, 100 students, 10 teachers, 500 MB
- Basic: ₦15,000/year, 500 students, 30 teachers, 2 GB
- Standard: ₦30,000/year, 1,500 students, 75 teachers, 5 GB
- Premium: ₦60,000/year, 5,000 students, 250 teachers, 15 GB

These defaults can be edited by Super Admin.

## Safety
- Existing schools remain `legacy` unless deliberately changed.
- No student, result, school, or tenant data is deleted when plans change.
- V26 displays student/teacher usage against plan limits but does not automatically block existing data entry when a limit is reached.
- Payment collection is not implemented in V26.
