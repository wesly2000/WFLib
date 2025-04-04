dataset=${1:-CW}
device=${2:-"cuda:1"}
checkpoints=${3:-normal}

python -u exp/test_specific.py \
  --dataset ${dataset} \
  --checkpoints ${checkpoints} \
  --model DF \
  --device ${device} \
  --feature DIR \
  --seq_len 5000 \
  --batch_size 256 \
  --eval_metrics Accuracy Precision Recall F1-score \
  --load_name max_f1 \
  --result_file ${checkpoints} 