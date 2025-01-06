dataset=${1:-CW}
device=${2:-"cuda:1"}
batch_size=${3:-128}

python -u exp/train.py \
  --dataset ${dataset} \
  --model DF \
  --device ${device} \
  --feature DIR \
  --seq_len 5000 \
  --train_epochs 30 \
  --batch_size ${batch_size} \
  --learning_rate 2e-3 \
  --optimizer Adamax \
  --eval_metrics Accuracy Precision Recall F1-score \
  --save_metric F1-score \
  --save_name max_f1

python -u exp/test.py \
  --dataset ${dataset} \
  --model DF \
  --device ${device} \
  --feature DIR \
  --seq_len 5000 \
  --batch_size 256 \
  --eval_metrics Accuracy Precision Recall F1-score \
  --load_name max_f1