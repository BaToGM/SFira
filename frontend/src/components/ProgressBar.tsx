type Props = {
  value: number;
  label: string;
};

export function ProgressBar({ value, label }: Props) {
  return (
    <div className="progress-block">
      <div className="row-between">
        <span>{label}</span>
        <strong>{value}%</strong>
      </div>
      <div className="progress-track" aria-label={label}>
        <div className="progress-fill" style={{ width: `${value}%` }} />
      </div>
    </div>
  );
}
