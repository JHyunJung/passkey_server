import * as React from "react";
import { X } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/cn";

export interface ChipInputProps {
  value: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  /** Validator; returning a non-empty string marks the input invalid and the chip is not added. */
  validate?: (candidate: string) => string | null;
  className?: string;
  inputId?: string;
}

export function ChipInput({
  value,
  onChange,
  placeholder,
  validate,
  className,
  inputId,
}: ChipInputProps) {
  const [draft, setDraft] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);

  const commit = React.useCallback(() => {
    const trimmed = draft.trim();
    if (!trimmed) return;
    if (value.includes(trimmed)) {
      setError("이미 추가된 항목입니다.");
      return;
    }
    const err = validate?.(trimmed) ?? null;
    if (err) {
      setError(err);
      return;
    }
    onChange([...value, trimmed]);
    setDraft("");
    setError(null);
  }, [draft, onChange, validate, value]);

  const remove = (idx: number) => {
    onChange(value.filter((_, i) => i !== idx));
  };

  return (
    <div className={cn("space-y-2", className)}>
      <div className="flex flex-wrap gap-2 rounded-md border border-input bg-background p-2 min-h-10">
        {value.map((chip, i) => (
          <Badge key={`${chip}-${i}`} variant="secondary" className="gap-1.5 pr-1">
            <span className="font-mono text-xs">{chip}</span>
            <button
              type="button"
              onClick={() => remove(i)}
              className="rounded-full p-0.5 hover:bg-foreground/10"
              aria-label={`Remove ${chip}`}
            >
              <X className="h-3 w-3" />
            </button>
          </Badge>
        ))}
        <Input
          id={inputId}
          value={draft}
          placeholder={placeholder}
          className="h-7 flex-1 min-w-[10rem] border-0 px-1 py-0 shadow-none focus-visible:ring-0"
          onChange={(e) => {
            setDraft(e.target.value);
            if (error) setError(null);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === ",") {
              e.preventDefault();
              commit();
            } else if (e.key === "Backspace" && !draft && value.length > 0) {
              remove(value.length - 1);
            }
          }}
          onBlur={commit}
        />
      </div>
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}
