# frozen_string_literal: true

# check a value and return a value depending on conditions

def check_value_string(val, default)
  if val.nil? || val.empty?
    default
  else
    val
  end
end

# check a value and return a boolean value depending on conditions

def check_value_boolean(val, default)
  ret = if default == true
          false
        else
          true
        end

  if val.nil? ||  val.empty?
    default
  else
    ret
  end
end
